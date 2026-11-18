// Allows a connection to start only when an external HTTP service approves
// the initiator's IP.
//
// IP_WHITELIST_URL         GET endpoint answering {"allowed": bool}. `{ip}` in
//                          the URL is replaced by the IP; without it, `ip=<IP>`
//                          is appended as a query parameter. Empty disables the
//                          check.
// IP_WHITELIST_TIMEOUT_MS  Request timeout (default 3000).
// IP_WHITELIST_FAIL_OPEN   "Y" lets connections through when the service cannot
//                          be reached or answers badly (default: denied).
// IP_WHITELIST_CACHE_MS    How long an answer from the service, allowed or denied,
//                          is reused for the same IP (default 10000, 0 disables).
//                          Failed checks are never cached.

use crate::common::get_arg;
use hbb_common::{bail, log, ResultType};
use moka::future::Cache;
use once_cell::sync::Lazy;
use serde_derive::Deserialize;
use std::{future::Future, net::IpAddr, sync::Arc, time::Duration};

const DEFAULT_TIMEOUT_MS: u64 = 3_000;
const DEFAULT_CACHE_MS: u64 = 10_000;
// Bound on cached IPs, so a flood of distinct addresses cannot grow memory without limit.
const CACHE_MAX_LEN: u64 = 65_536;

struct Config {
    url: String,
    fail_open: bool,
    client: Option<reqwest::Client>,
    cache_ms: u64,
    cache: Option<Cache<IpAddr, bool>>,
}

#[derive(Deserialize)]
struct Answer {
    allowed: bool,
}

static CONFIG: Lazy<Config> = Lazy::new(|| {
    let url = get_arg("IP_WHITELIST_URL").trim().to_owned();
    let timeout = get_arg("IP_WHITELIST_TIMEOUT_MS")
        .parse::<u64>()
        .ok()
        .filter(|ms| *ms > 0)
        .unwrap_or(DEFAULT_TIMEOUT_MS);
    let fail_open = get_arg("IP_WHITELIST_FAIL_OPEN").to_uppercase() == "Y";
    let cache_ms = get_arg("IP_WHITELIST_CACHE_MS")
        .parse::<u64>()
        .unwrap_or(DEFAULT_CACHE_MS);
    let client = if url.is_empty() {
        None
    } else {
        match reqwest::Client::builder()
            .timeout(Duration::from_millis(timeout))
            .build()
        {
            Ok(client) => Some(client),
            Err(err) => {
                log::error!("IP whitelist: failed to build HTTP client: {err}");
                None
            }
        }
    };
    let cache = (cache_ms > 0).then(|| new_cache(Duration::from_millis(cache_ms)));
    Config {
        url,
        fail_open,
        client,
        cache_ms,
        cache,
    }
});

fn new_cache(ttl: Duration) -> Cache<IpAddr, bool> {
    Cache::builder()
        .max_capacity(CACHE_MAX_LEN)
        .time_to_live(ttl)
        .build()
}

/// Whether an IP whitelist URL is configured.
pub fn is_enabled() -> bool {
    !CONFIG.url.is_empty()
}

/// Logs the whitelist settings and refuses to run it without a key, so that
/// anonymous connections cannot make the server query the whitelist service.
pub fn check_config(key: &str) -> ResultType<()> {
    let cfg = &*CONFIG;
    if !is_enabled() {
        log::info!("IP_WHITELIST_URL not set, initiator IP check disabled");
        return Ok(());
    }
    if key.is_empty() {
        bail!("IP_WHITELIST_URL requires a key (-k); refusing to start");
    }
    log::info!(
        "IP_WHITELIST_URL={} fail_open={} cache_ms={}",
        cfg.url,
        cfg.fail_open,
        cfg.cache_ms
    );
    Ok(())
}

fn build_url(base: &str, ip: &IpAddr) -> String {
    let ip = ip.to_string();
    if base.contains("{ip}") {
        return base.replace("{ip}", &ip);
    }
    let sep = if base.contains('?') { '&' } else { '?' };
    // IPv6 colons are valid in a query string, so the IP needs no escaping.
    format!("{base}{sep}ip={ip}")
}

async fn query(client: &reqwest::Client, url: &str) -> Result<bool, String> {
    let res = client.get(url).send().await.map_err(|e| e.to_string())?;
    let status = res.status();
    if !status.is_success() {
        return Err(format!("HTTP {status}"));
    }
    let bytes = res.bytes().await.map_err(|e| e.to_string())?;
    let answer: Answer = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    Ok(answer.allowed)
}

/// Runs `check` for `ip` through `cache`, when there is one. Only successful
/// answers are cached, and concurrent calls for the same IP share one `check`.
/// On success, also tells whether the answer was reused rather than computed here.
async fn cached_check(
    cache: Option<&Cache<IpAddr, bool>>,
    ip: IpAddr,
    check: impl Future<Output = Result<bool, String>>,
) -> Result<(bool, bool), Arc<String>> {
    let Some(cache) = cache else {
        return check.await.map(|allowed| (allowed, false)).map_err(Arc::new);
    };
    let entry = cache.entry(ip).or_try_insert_with(check).await?;
    Ok((*entry.value(), !entry.is_fresh()))
}

/// Whether `ip` may start a connection. Always true when no URL is configured.
pub async fn is_allowed(ip: IpAddr) -> bool {
    let cfg = &*CONFIG;
    if cfg.url.is_empty() {
        return true;
    }
    let Some(client) = cfg.client.as_ref() else {
        return cfg.fail_open;
    };
    let url = build_url(&cfg.url, &ip);
    match cached_check(cfg.cache.as_ref(), ip, query(client, &url)).await {
        Ok((allowed, reused)) => {
            if !allowed {
                log::info!(
                    "IP whitelist denied {ip}{}",
                    if reused { " (cached)" } else { "" }
                );
            }
            allowed
        }
        Err(err) => {
            log::warn!(
                "IP whitelist check for {ip} failed: {err}, {}",
                if cfg.fail_open { "allowing" } else { "denying" }
            );
            cfg.fail_open
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::tokio;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn url_placeholder_and_query() {
        let v4: IpAddr = "1.2.3.4".parse().unwrap();
        let v6: IpAddr = "::1".parse().unwrap();
        assert_eq!(
            build_url("http://x/check/{ip}", &v4),
            "http://x/check/1.2.3.4"
        );
        assert_eq!(build_url("http://x/check", &v4), "http://x/check?ip=1.2.3.4");
        assert_eq!(build_url("http://x/c?k=1", &v6), "http://x/c?k=1&ip=::1");
    }

    fn ip() -> IpAddr {
        "1.2.3.4".parse().unwrap()
    }

    #[hbb_common::tokio::test]
    async fn a_denied_answer_is_cached() {
        let cache = new_cache(Duration::from_secs(60));
        let first = cached_check(Some(&cache), ip(), async { Ok(false) }).await;
        assert_eq!(first, Ok((false, false)));
        let second = cached_check(Some(&cache), ip(), async { Ok(true) }).await;
        assert_eq!(second, Ok((false, true)));
    }

    #[hbb_common::tokio::test]
    async fn a_failed_check_is_not_cached() {
        let cache = new_cache(Duration::from_secs(60));
        let failed = cached_check(Some(&cache), ip(), async { Err("down".to_owned()) }).await;
        assert_eq!(failed, Err(Arc::new("down".to_owned())));
        let retried = cached_check(Some(&cache), ip(), async { Ok(true) }).await;
        assert_eq!(retried, Ok((true, false)));
    }

    #[hbb_common::tokio::test]
    async fn an_answer_expires_after_the_cache_period() {
        let cache = new_cache(Duration::from_millis(50));
        let _ = cached_check(Some(&cache), ip(), async { Ok(false) }).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let later = cached_check(Some(&cache), ip(), async { Ok(true) }).await;
        assert_eq!(later, Ok((true, false)));
    }

    #[hbb_common::tokio::test]
    async fn without_a_cache_every_call_checks() {
        let first = cached_check(None, ip(), async { Ok(false) }).await;
        let second = cached_check(None, ip(), async { Ok(true) }).await;
        assert_eq!((first, second), (Ok((false, false)), Ok((true, false))));
    }

    #[hbb_common::tokio::test]
    async fn concurrent_checks_for_one_ip_query_once() {
        let cache = new_cache(Duration::from_secs(60));
        let queries = AtomicUsize::new(0);
        let check = || async {
            queries.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(50)).await;
            Ok(true)
        };
        let (a, b, c) = tokio::join!(
            cached_check(Some(&cache), ip(), check()),
            cached_check(Some(&cache), ip(), check()),
            cached_check(Some(&cache), ip(), check()),
        );
        assert!([a, b, c].iter().all(|r| matches!(r, Ok((true, _)))));
        assert_eq!(queries.load(Ordering::SeqCst), 1);
    }
}

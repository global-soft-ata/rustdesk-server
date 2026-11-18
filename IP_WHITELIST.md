# Whitelist de IP (hbbs + hbbr)

Uma conexão só pode ser **iniciada** quando um serviço HTTP externo aprova o IP de
quem a inicia. A lógica fica em [`src/ip_whitelist.rs`](src/ip_whitelist.rs) e é
usada pelo hbbs e pelo hbbr.

## Configuração

Igual nos dois binários, por variável de ambiente ou pelo `.env`:

| Variável | Descrição |
| --- | --- |
| `IP_WHITELIST_URL` | Endpoint GET que responde `{"allowed": bool}`. `{ip}` na URL é trocado pelo IP; sem `{ip}`, é adicionado `?ip=<IP>`. Se ficar vazio, a checagem é desligada. |
| `IP_WHITELIST_TIMEOUT_MS` | Timeout da requisição (padrão `3000`). |
| `IP_WHITELIST_FAIL_OPEN` | `Y` deixa passar quando o serviço está fora do ar ou responde algo inválido. O padrão é negar. |
| `IP_WHITELIST_CACHE_MS` | Por quanto tempo a resposta do serviço para um IP, liberado **ou negado**, é reaproveitada (padrão `10000`; `0` desliga). Falhas de consulta não entram no cache. |

> **Atenção:** o hbbr agora também lê essas variáveis. Elas precisam estar
> definidas no ambiente do hbbr, já que o `run-hbbs.sh` só configura o hbbs.

Na inicialização, os dois servidores registram no log se a checagem está ativa
(`IP_WHITELIST_URL=... fail_open=...`) ou desligada.

## Onde a checagem acontece

### hbbs ([`src/rendezvous_server.rs`](src/rendezvous_server.rs))

- **`PunchHoleRequest`** (TCP/WebSocket): se o IP for negado, o servidor responde
  com `PunchHoleResponse.other_failure = "Your IP is not allowed to connect"`.
- **`RequestRelay`**: se o IP for negado, responde com
  `RelayResponse.refuse_reason` contendo a mesma mensagem, e o pedido não é
  repassado ao peer.

### hbbr ([`src/relay_server.rs`](src/relay_server.rs), função `make_pair_`)

Cada sessão de relay tem duas conexões com o mesmo `uuid`. Só a do
**iniciador** envia `RequestRelay.id` preenchido (o ID do destino). A conexão do
lado controlado manda só o `uuid`. Só o iniciador precisa estar na whitelist: o
IP do controlado nunca é consultado e nunca libera nada.

1. **Checagem do iniciador:** logo depois da validação da key, a conexão com
   `id` preenchido é checada. Se o IP for negado, o hbbr fecha a conexão sem
   resposta (o protocolo do relay não tem mensagem de recusa) antes de ela ficar
   esperando ou ser pareada. O log registra
   `Relay request <uuid> from <addr> (socket <ip>) to <id> denied: IP not allowed`.
2. **Regra do par:** com a whitelist ativa, um par só é formado se pelo menos
   uma das duas conexões for um iniciador aprovado. Sem isso, duas conexões com
   `id` vazio (por exemplo, um script que controla as duas pontas e usa o relay
   como túnel) seriam pareadas sem passar pela whitelist. Nesse caso, as duas
   são fechadas sem consultar a API, e o log registra
   `Relay pair <uuid> ... refused: no whitelisted initiator`.

| Situação | Resultado |
| --- | --- |
| Iniciador liberado (com `id`) + controlado (sem `id`) | pareia, com uma consulta |
| Iniciador não liberado (com `id`) | fechado antes de esperar |
| Duas conexões sem `id` | par recusado, sem consultar a API |

Com a whitelist desligada, o pareamento funciona como no upstream.

Para isso, [`src/hbbr.rs`](src/hbbr.rs) passou a declarar `mod ip_whitelist;`, e
`start_with_bind` chama `ip_whitelist::check_config(&key)`.

### Key obrigatória

Com `IP_WHITELIST_URL` definido, hbbs e hbbr **se recusam a iniciar sem key**
(`IP_WHITELIST_URL requires a key (-k); refusing to start`). Isso impede que
conexões anônimas façam o servidor consultar a API. O hbbs já gera uma key por
padrão (`-`), mas o hbbr não, então nele é preciso passar `-k`. Os serviços
instalados usam `-k _`. A key é a chave pública distribuída aos clientes, então
ela reduz o abuso casual, mas não é um segredo.

## Proteção contra spoofing por `X-Real-IP` / `X-Forwarded-For`

Nas portas WebSocket (hbbs `21118`, hbbr `21119`), o código original **troca**
o endereço do cliente pelo valor dos headers `X-Real-IP`/`X-Forwarded-For`, sem
validar nada. Se a whitelist usasse esse endereço, bastaria um cliente mandar
`X-Real-IP: <ip liberado>` para passar pela checagem.

Por isso, os dois servidores agora guardam o **IP real do socket TCP**
(`socket_ip`) **antes** do handshake WebSocket, e a whitelist usa sempre ele:

- hbbr: `make_pair` guarda `socket_ip` e o passa para `make_pair_`.
- hbbs: `handle_listener_inner` guarda `socket_ip` e o passa por
  `handle_tcp` → `handle_tcp_punch_hole_request` → `handle_punch_hole_request`.

O `addr` derivado dos headers continua sendo usado em logs, blocklist e
roteamento, como antes. Os logs de recusa mostram os dois valores.

**Consequência:** se as portas WebSocket ficarem atrás de um reverse proxy
(WSS), a whitelist vai ver o IP do **proxy**, e não o do cliente. Nesse cenário,
é preciso liberar o IP do proxy (o que libera todo mundo que passa por ele) ou
fazer a filtragem no próprio proxy. Pelas portas TCP comuns (21116/21117) isso
não acontece.

## Limitações conhecidas

- A regra do par depende de o cliente RustDesk do técnico mandar `id` no
  `RequestRelay` ao relay, o que o cliente oficial faz. Se uma sessão legítima
  via relay for recusada com `no whitelisted initiator`, a causa é essa.
- Cache: liberar ou bloquear um IP no serviço pode levar até
  `IP_WHITELIST_CACHE_MS` para valer. Cada processo (hbbs e hbbr) tem o seu
  próprio cache em memória. Ele só guarda respostas válidas: se a consulta
  falhar (timeout, HTTP de erro, JSON inválido), vale o `FAIL_OPEN` e a próxima
  conexão consulta de novo. O cache usa a lib
  [`moka`](https://crates.io/crates/moka) (`future::Cache`): validade por
  entrada, teto de 65 536 IPs (a moka descarta as entradas menos úteis) e
  limpeza incremental. Conexões simultâneas do mesmo IP com o cache vazio geram
  **uma** consulta ao Gestor; as demais esperam a mesma resposta.
- Dependência: o `ed25519` 1.5.0 declara `signature = ">=1.3.1"`, sem limite
  superior. Ao re-resolver o grafo (como no `cargo add moka`), o cargo junta o
  `signature` 1.5.0 com o 2.2.0 e a compilação quebra. O `Cargo.lock` mantém o
  `ed25519` apontando para o `signature 1.5.0`; se ele for regenerado, é
  preciso refazer esse ajuste.

## Verificação

- `cargo build --bin hbbs --bin hbbr`: compila sem warnings novos.
- `cargo test --bin hbbr --lib`: todos os testes existentes passam (13 + 12).
- Teste de ponta a ponta com um hbbr real e um script que abre as duas conexões
  (pelo IP da LAN, porque conexões TCP de loopback caem no console
  administrativo do hbbr):

  | Cenário | Resultado |
  | --- | --- |
  | Whitelist ativa, duas conexões sem `id` | recusado (`no whitelisted initiator`) |
  | Whitelist ativa, iniciador negado | iniciador fechado (`denied: IP not allowed`) |
  | Whitelist ativa, iniciador liberado | pareado, dados repassados |
  | Whitelist desligada, duas conexões sem `id` | pareado (comportamento do upstream) |
  | Whitelist ativa, hbbr sem `-k` | não inicia |

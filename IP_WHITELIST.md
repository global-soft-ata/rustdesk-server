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

A checagem roda logo depois da validação da key e **antes** de a conexão ser
colocada em espera ou pareada:

- Cada sessão de relay tem duas pernas com o mesmo `uuid`. Só a do **iniciador**
  envia `RequestRelay.id` preenchido (o ID do destino). A perna do lado controlado
  manda só o `uuid`.
- Por isso só a perna com `id` preenchido é checada. O dispositivo controlado
  não precisa estar na whitelist.
- Se o IP for negado, o hbbr fecha a conexão sem resposta (o protocolo do relay
  não tem mensagem de recusa) e registra
  `Relay request <uuid> from <addr> (socket <ip>) to <id> denied: IP not allowed`.

Para isso, [`src/hbbr.rs`](src/hbbr.rs) passou a declarar `mod ip_whitelist;`, e
`start_with_bind` chama `ip_whitelist::log_config()`.

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

- Um cliente modificado poderia omitir `RequestRelay.id` no hbbr para escapar da
  checagem. Mesmo assim, ele não consegue montar uma sessão sozinho: o lado
  controlado só se conecta ao hbbr quando o hbbs manda (via `RequestRelay` ou
  `PunchHole`), e o hbbs já checou o IP do iniciador. Na prática, o hbbs é a
  barreira principal e o hbbr é uma defesa em profundidade.
- Não há cache de respostas: cada pedido gera uma requisição HTTP.

## Verificação

- `cargo build --bin hbbs --bin hbbr`: compila sem warnings novos.
- `cargo test --bin hbbr --lib`: todos os testes existentes passam (13 + 12).

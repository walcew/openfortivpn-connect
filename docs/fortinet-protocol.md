# Protocolo Fortinet SSL VPN no Engine

O que o Engine Fortinet do Helper (`src-tauri/helper/src/fortinet/`) implementa hoje: login por senha, configuração do túnel, túnel TLS com PPP e logout. Escrito do zero a partir do comportamento observado do FortiClient (doc de engenharia reversa do `vpn-client`, seções 4 e 5), das RFCs do PPP (1661 e 1332, DNS na 1877) e do comportamento público de clientes de terceiros. Nenhum código de openfortivpn ou openconnect foi copiado ou traduzido.

Marcas: **obs** = visto no FortiClient ou no gateway real; **rfc** = padrão PPP; **inf** = inferência, ainda sem prova contra o gateway real.

## Conexões

Cada passo HTTP abre uma conexão TLS nova com `Connection: close`. O certificado do gateway é aceito só se o sha256 do DER dele estiver em `trusted_certs` do Profile, no mesmo formato hex minúsculo do app. Raízes do sistema e auto-trust ficam para o ticket #14, no mesmo verificador (`GatewayCertVerifier` em `fortinet/http.rs`).

## 1. Login por senha

`POST /remote/logincheck` com corpo `application/x-www-form-urlencoded`:

```
username=<usuário>&credential=<senha>&realm=&just_logged_in=1&redir=%2Fremote%2Findex&ajax=1
```

Os campos e a ordem são os do passo comum do FortiClient (**obs**), que lá vai com `username` e `credential` vazios, depois do SAML. Preencher os dois com usuário e senha no login por senha é **inf**.

- Sucesso: `Set-Cookie: SVPNCOOKIE=<valor>` com valor não vazio (**obs**).
- Falha: o cookie não vem ou vem vazio, e o corpo traz `ret=0` (**inf**). O Engine trata qualquer ausência de cookie como credencial inválida. OTP e push (`ret=2` com pedido de token) ficam para o ticket próprio.

## 2. Configuração do túnel

`GET /remote/fortisslvpn_xml` com `Host: sslvpn` e `Cookie: SVPNCOOKIE=<valor>`, sem `dual_stack` (**obs**). Login e logout usam o host do gateway no `Host`. O Engine lê do XML, em qualquer nível do documento:

| Elemento | Uso |
|---|---|
| `<dns ip="..."/>` | servidores DNS |
| `<dns-suffix str="a;b"/>` | sufixos DNS; mais de um separado por `;` (**inf**) |
| `<split-tunnel-info><addr ip="..." mask="..."/></split-tunnel-info>` | rotas do split tunnel |
| `<auth-timeout val="segundos"/>` | `expires_at` = agora + val; `0` = sem expiração |
| `<mtu val="..."/>` | MTU; o nome do elemento é **inf**, sem ele vale 1354 |

Sem nenhum `<addr>` em `split-tunnel-info`, o túnel é full tunnel (**inf**). `assigned-addr` é ignorado: vale o IP do IPCP.

## 3. Túnel

Nova conexão TLS e, nela:

```
GET /remote/sslvpn-tunnel HTTP/1.1
Host: sslvpn
Cookie: SVPNCOOKIE=<valor>
```

O gateway não responde com HTTP quando aceita: o stream passa direto a carregar quadros PPP (**inf**). Se os primeiros bytes forem `HTTP/`, é recusa e a conexão falha com a linha de status.

### Quadro

Cada quadro tem um cabeçalho de 6 bytes, big-endian:

| Bytes | Campo |
|---|---|
| 0–1 | tamanho total do quadro (cabeçalho + PPP) |
| 2–3 | magic `0x5050` |
| 4–5 | tamanho do PPP |

Depois vem o PPP sem HDLC (sem flags, escape nem FCS). O Engine envia o campo de endereço e controle `FF 03` antes do protocolo, como manda o PPP sem ACFC negociado (**rfc**), e aceita quadros com ou sem ele (**inf**: o formato exato que o gateway envia não foi confirmado). Quadro com magic errado ou tamanhos inconsistentes derruba o túnel.

### PPP

- **LCP** (`0xC021`): o Engine pede MRU (= MTU) e Magic-Number. Do gateway aceita MRU, ACCM e Magic-Number e rejeita o resto (autenticação, PFC, ACFC). Nak troca o valor da opção e Reject a remove; nos dois casos o pedido é refeito (**rfc**). Echo-Request do gateway recebe Echo-Reply com o nosso magic. Terminate-Request recebe Terminate-Ack e encerra o túnel.
- **IPCP** (`0x8021`): começa quando o LCP abre. O Engine pede IP-Address `0.0.0.0` e DNS primário e secundário (129 e 131) zerados; o gateway responde com Nak trazendo os valores atribuídos, e o pedido é refeito com eles (**rfc**). Do gateway aceita só IP-Address, que vira o peer. IPCP aberto com IP `0.0.0.0` é erro.
- **IP** (`0x0021`): depois do IPCP, pacotes IPv4 passam nos dois sentidos entre o túnel e o canal da camada de rede.
- Outros protocolos (IPv6CP, CCP) recebem Protocol-Reject depois que o LCP abre. Não há IPv6CP.

DNS do XML tem prioridade; os do IPCP só valem se o XML não trouxer nenhum (**inf**).

## 4. Logout

`GET /remote/logout` com o cookie, no disconnect pedido pelo usuário, com prazo de 2 s (**obs**: o FortiClient chama no fim da sessão). Resposta e erro são ignorados.

## O que ainda não está aqui

`/remote/info`, OTP, push, SAML, LCP echo do cliente para detectar túnel morto, aviso e teardown na expiração, DTLS, `tun`/`websocket` e IPv6.

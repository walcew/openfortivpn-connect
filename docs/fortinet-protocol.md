# Protocolo Fortinet SSL VPN no Engine

O que o Engine Fortinet do Helper (`src-tauri/helper/src/fortinet/`) implementa hoje: login por senha com OTP e FortiToken push, configuração do túnel, túnel TLS com PPP e logout. Escrito do zero a partir do comportamento observado do FortiClient (doc de engenharia reversa do `vpn-client`, seções 4 e 5), das RFCs do PPP (1661 e 1332, DNS na 1877) e do comportamento público de clientes de terceiros. Nenhum código de openfortivpn ou openconnect foi copiado ou traduzido.

Marcas: **obs** = visto no FortiClient ou no gateway real; **rfc** = padrão PPP; **inf** = inferência, ainda sem prova contra o gateway real.

## Conexões

Cada passo HTTP abre uma conexão TLS nova com `Connection: close`. O certificado do gateway é validado em `GatewayCertVerifier` (`fortinet/http.rs`), criado por conexão do Profile. Com `ignore_cert_errors: false`, é aceito se a cadeia valer pelas raízes do sistema (`rustls-platform-verifier`, para o host do Profile) ou se o sha256 do DER estiver em `trusted_certs` (hex minúsculo, como no app); sem nenhum dos dois, o erro traz o motivo do verificador e o digest (`untrusted gateway certificate (<motivo>), sha256 digest <hex>`), e o estado `disconnected` do contrato v2 leva o campo opcional `cert_digest` (sha256 hex) com o mesmo digest, que é o que a GUI lê. Com `ignore_cert_errors: true` (auto-trust), qualquer certificado é aceito, só para o host daquele Profile, e as assinaturas do handshake continuam verificadas. O Helper guarda em memória o digest da última conexão por host e, quando ele muda, registra um log (`gateway certificate of <host> changed: sha256 <antigo> -> <novo>`) depois do handshake concluir, que prova a posse da chave; o histórico se perde quando o Helper reinicia.

## 1. Login por senha

`POST /remote/logincheck` com corpo `application/x-www-form-urlencoded`:

```
username=<usuário>&credential=<senha>&realm=&just_logged_in=1&redir=%2Fremote%2Findex&ajax=1
```

Os campos e a ordem são os do passo comum do FortiClient (**obs**), que lá vai com `username` e `credential` vazios, depois do SAML. Preencher os dois com usuário e senha no login por senha é **inf**.

- Sucesso: `Set-Cookie: SVPNCOOKIE=<valor>` com valor não vazio (**obs**).
- Falha: o cookie não vem ou vem vazio, e o corpo traz `ret=0` (**inf**). Sem cookie e sem `tokeninfo` no corpo, o Engine trata como credencial inválida.

### Segundo passo: OTP e push

Quando o gateway exige token, o primeiro `logincheck` volta sem cookie e com um corpo de pares `chave=valor` separados por vírgula (**inf**: formato e nomes vêm do comportamento público de clientes de terceiros, sem prova contra o gateway real):

```
ret=2,tokeninfo=<tipo>,chal_msg=<texto>,reqid=..,polid=..,grp=..,portal=..,peer=..,magic=..
```

- A presença da chave `tokeninfo` marca o pedido de token. `tokeninfo=ftm_push` indica que o gateway oferece push do FortiToken Mobile; outro valor (ou vazio) é código digitado (**inf**).
- O Engine guarda `reqid`, `polid`, `grp`, `portal`, `peer` e `magic` e ignora o resto. Valor com vírgula vem truncado (`chal_msg` não importa).
- O segundo passo é outro `POST /remote/logincheck`, no mesmo formato de formulário, com `username`, os seis valores devolvidos como vieram, e `code=<otp>` **ou** `ftm_push=1`, mais `just_logged_in=1&ajax=1` (**inf**: o conjunto exato de campos). O `credential` não é reenviado (**inf**).
- Com OTP no `connect`, o Engine manda `code`. Sem OTP e com push oferecido, manda `ftm_push=1`, emite o estado `waiting-push` e espera a resposta por até 60 s (**inf**: se o gateway segura a resposta até a aprovação ou exige novas consultas não foi confirmado; o prazo é escolha nossa). Sem OTP e sem push, o login falha com "requires an OTP".
- Sucesso é o mesmo `Set-Cookie: SVPNCOOKIE` não vazio. Sem cookie, o código errado ou expirado e o push recusado ou expirado viram `disconnected` com `reason`. OTP enviado a um gateway que não pede token é ignorado.
- O OTP só trafega no corpo do `connect` (socket) e no corpo do `POST` (TLS); nunca em argv nem em log.

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

`/remote/info`, SAML, LCP echo do cliente para detectar túnel morto, aviso e teardown na expiração, DTLS, `tun`/`websocket` e IPv6.

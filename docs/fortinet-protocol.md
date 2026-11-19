# Protocolo Fortinet SSL VPN no Engine

O que o Engine Fortinet do Helper (`src-tauri/helper/src/fortinet/`) implementa hoje: login por senha com OTP e FortiToken push, login SAML pelo navegador externo, configuração do túnel, túnel TLS com PPP e logout. Escrito do zero a partir do comportamento observado do FortiClient (doc de engenharia reversa do `vpn-client`, seções 4 e 5), das RFCs do PPP (1661 e 1332, DNS na 1877) e do comportamento público de clientes de terceiros. Nenhum código de openfortivpn ou openconnect foi copiado ou traduzido.

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

Quando o gateway exige o segundo fator, o primeiro `logincheck` volta sem cookie e com um corpo de pares `chave=valor` separados por vírgula (**inf**: formato e nomes vêm do comportamento público de clientes de terceiros, sem prova contra o gateway real):

```
ret=2,tokeninfo=<tipo>,chal_msg=<texto>,reqid=..,polid=..,grp=..,portal=..,peer=..,magic=..
```

- A presença da chave `tokeninfo` marca o pedido do segundo fator. `tokeninfo=ftm_push` indica que o gateway oferece push do FortiToken Mobile; outro valor (ou vazio) é código digitado (**inf**).
- O Engine guarda `reqid`, `polid`, `grp`, `portal`, `peer` e `magic` e ignora o resto. Valor com vírgula vem truncado (`chal_msg` não importa). Sem `reqid` o login falha com "incomplete login challenge", e não como OTP inválido; os outros cinco são reenviados se vierem, mas não são exigidos (**inf**: quais campos o gateway real sempre manda).
- O segundo passo é outro `POST /remote/logincheck`, no mesmo formato de formulário, com `username`, os seis valores devolvidos como vieram, e `code=<otp>` **ou** `ftm_push=1`, mais `just_logged_in=1&ajax=1` (**inf**: o conjunto exato de campos). O `credential` não é reenviado (**inf**).
- Com OTP no `connect`, o Engine manda `code`. Sem OTP e com push oferecido, manda `ftm_push=1`, emite o estado `waiting-push` e espera a resposta por até 60 s. Passado o prazo, o login falha com "push notification expired". Que o gateway segure a resposta até a aprovação (e não exija novas consultas) é **inf**; os 60 s são escolha nossa. Sem OTP e sem push, o login falha com "requires an OTP".
- O nome do campo do push é **inf**: o Engine usa `ftm_push=1`, mas clientes de terceiros também usam a variante `ftmpush=1`. Os dois ficam sem validação até o teste contra o gateway real.
- Cancelar durante `waiting-push` não faz logout: o Engine ainda não tem cookie. Se o usuário aprovar o push depois de cancelar, a sessão fica aberta no gateway até expirar.
- Sucesso é o mesmo `Set-Cookie: SVPNCOOKIE` não vazio. Sem cookie, o código errado ou expirado e o push recusado ou expirado viram `disconnected` com `reason`. OTP enviado a um gateway que não pede token é ignorado.
- O OTP só trafega no corpo do `connect` (socket) e no corpo do `POST` (TLS); nunca em argv nem em log.

### SAML pelo navegador externo

O fluxo externo do FortiClient (doc de engenharia reversa, seção 4), com o Profile `auth: "saml"`, sem username nem senha:

1. `GET /remote/info` com o host do gateway. O Engine lê os atributos `sso_port='<n>'` e `remoteauthtimeout='<s>'` do corpo, com aspas simples ou duplas (**obs**: `remoteauthtimeout='120' sso_port='8020'`; o resto do formato do corpo não importa). O prazo do login é o `remoteauthtimeout` (**obs**: o FortiClient usa o menor entre o pedido e esse valor; o Engine não pede outro). Resposta fora de 2xx, ou sem um dos campos, segue com 8020 e 120 s, os do gateway testado, e registra um aviso no log.
2. Escuta em `127.0.0.1:<sso_port>`, nunca em `0.0.0.0`. Porta ocupada (o próprio FortiClient usa a 8020) vira `disconnected` com "Local SSO port <n> is already in use; close the app using it (e.g. FortiClient) and try again".
3. Emite o estado `waiting-saml` com `url` = `https://<host>[:<porta>]/remote/saml/start?redirect=1` (porta omitida quando é 443). A GUI abre a URL no navegador padrão, porque o Helper roda como root (**obs**: a URL é a do FortiClient).
4. O navegador chega ao listener com `GET /?id=<id>`. Conexões vazias (o navegador abre de 2 a 5 antes da real, **obs**), que não mandam o cabeçalho em 10 s ou com mais de 8 KB são fechadas sem resposta. No máximo 16 conexões ficam abertas ao mesmo tempo; acima disso a nova é fechada na hora, para um processo local não esgotar os descritores do Helper. Só vale `GET` no caminho `/` com `?id=<id>`: o `id` vai até o primeiro espaço ou `&` e precisa ter de 1 a 1024 caracteres entre letras, dígitos e `-_.~%` (**inf**: o formato real do `id` não foi visto). Válido, a resposta é `HTTP/1.1 200 OK` com uma página dizendo que a aba pode ser fechada, e o listener fecha. Qualquer outro pedido (outro método, outro caminho, `id` ausente ou malformado) recebe `400` e o listener continua escutando até um `id` válido ou o prazo: uma página web que aponte para a porta não derruba o login.
5. `GET /remote/saml/auth_id?id=<id>`. Se a resposta trouxer `Set-Cookie: SVPNCOOKIE=<valor>` não vazio, o login acabou. **inf**: é onde o openfortivpn lê o cookie; onde o cookie aparece é a pergunta aberta nº 1 da spec, a confirmar contra o gateway real.
6. Sem o cookie ali, o passo comum do FortiClient (**obs**): `POST /remote/logincheck` com `username=&credential=&just_logged_in=1&redir=%2Fremote%2Findex&ajax=1`, levando no `Cookie` os cookies com valor que o `auth_id` deixou (**inf**: o FortiClient usa o pote de cookies do WinINet, então que o gateway amarre a sessão por cookie do `auth_id` é inferência). Sem `SVPNCOOKIE` também aqui, `disconnected` com "the gateway returned no session cookie".
7. Daí em diante o fluxo é o mesmo da senha (seções 2 a 4).

- Passado o prazo sem o `id`, `disconnected` com "SAML login timed out after <s> s".
- O comando `cancel` (ou `disconnect`) durante a espera fecha o listener e volta a `disconnected` sem `reason`. Não há logout: ainda não existe cookie. O cancelamento é marcado sob o mesmo lock do estado: se chegar enquanto o login ainda está pendente, a sessão nunca anuncia `connected`, mesmo que o túnel termine de subir logo depois; com a sessão já conectada, o `cancel` não faz nada.
- **Risco residual (login CSRF):** quem tiver um `id` SAML válido do mesmo gateway, obtido com a própria conta, e conseguir entregá-lo primeiro ao listener local (por exemplo com uma página web aberta durante a espera) prende a vítima na sessão VPN dele. O item 4 só mitiga em parte: pedidos malformados não derrubam mais o login, mas um `id` bem formado é aceito sem prova de que veio do navegador da vítima, e o protocolo não oferece um valor por login para amarrar o `id` ao `start` (**inf**).
- O cookie fica no Helper: não vai em evento, log nem resposta. O `id` também não vai para o log.

## 2. Configuração do túnel

`GET /remote/fortisslvpn_xml` com `Host: sslvpn` e `Cookie: SVPNCOOKIE=<valor>`, sem `dual_stack` (**obs**). Login e logout usam o host do gateway no `Host`. O Engine lê do XML, em qualquer nível do documento:

| Elemento | Uso |
|---|---|
| `<dns ip="..."/>` | servidores DNS |
| `<dns-suffix str="a;b"/>` | sufixos DNS; mais de um separado por `;` (**inf**) |
| `<split-tunnel-info><addr ip="..." mask="..."/></split-tunnel-info>` | rotas do split tunnel |
| `<auth-timeout val="segundos"/>` | `expires_at` = início do login + val; `0` = sem expiração |
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

- **LCP** (`0xC021`): o Engine pede MRU (= MTU) e Magic-Number. Do gateway aceita MRU, ACCM e Magic-Number e rejeita o resto (autenticação, PFC, ACFC). Nak troca o valor da opção e Reject a remove; nos dois casos o pedido é refeito (**rfc**). Echo-Request do gateway recebe Echo-Reply com o nosso magic. Terminate-Request recebe Terminate-Ack e encerra o túnel. Com o IPCP aberto, o Engine manda um Echo-Request (com o nosso magic) a cada 10 s; veja "Túnel morto e expiração".
- **IPCP** (`0x8021`): começa quando o LCP abre. O Engine pede IP-Address `0.0.0.0` e DNS primário e secundário (129 e 131) zerados; o gateway responde com Nak trazendo os valores atribuídos, e o pedido é refeito com eles (**rfc**). Do gateway aceita só IP-Address, que vira o peer. IPCP aberto com IP `0.0.0.0` é erro.
- **IP** (`0x0021`): depois do IPCP, pacotes IPv4 passam nos dois sentidos entre o túnel e o canal da camada de rede.
- Outros protocolos (IPv6CP, CCP) recebem Protocol-Reject depois que o LCP abre. Não há IPv6CP.

DNS do XML tem prioridade; os do IPCP só valem se o XML não trouxer nenhum (**inf**). Isso diverge do v1: lá, sem DNS no XML, o `dns_fallback` (DNS do sistema mais Google) entra mesmo que o IPCP traga DNS; no v2 o fallback só entra se nem o XML nem o IPCP trouxerem (o DNS do IPCP é o do próprio gateway).

### Túnel morto e expiração

- **Echo:** com o túnel de pé, um Echo-Request sai a cada 10 s (o primeiro 10 s depois de abrir o túnel). Qualquer pacote LCP do gateway (Echo-Reply, Echo-Request dele etc.) zera a contagem. No terceiro tick seguido sem nenhum LCP do gateway o túnel cai, cerca de 30 s depois da última resposta, com o motivo `Tunnel dropped: no response from the gateway` (**rfc** para o echo; os 10 s e os 3 intervalos são escolha nossa, da spec).
- **Escrita travada:** toda escrita no túnel tem prazo de 3 intervalos de echo (30 s). Num TCP meio aberto com tráfego, o buffer de envio enche e a escrita travaria o laço, e com ele o echo; estourado o prazo, o túnel cai com `Tunnel dropped: write timed out`. Erro de escrita vira `Tunnel dropped: write failed: ...`.
- **TLS fechado e PPP encerrado:** EOF no stream vira `Tunnel dropped: connection closed by the gateway`, erro de leitura vira `Tunnel dropped: read failed: ...` e Terminate-Request do gateway vira `Tunnel dropped: the gateway terminated the PPP session`.
- **Expiração:** `expires_at` é o início do login + `auth-timeout` (push e SAML podem levar minutos antes do túnel). Ele dispara o evento `expiring` 15 min antes (ou logo ao conectar, se faltar menos que isso) e, no horário, encerra a sessão com o motivo `Session expired`. Sem `auth-timeout` (ou com `0`), não há aviso nem encerramento por tempo. Além de dormir até o próximo prazo, o Helper confere o relógio de parede a cada 10 s: o relógio monotônico para durante o sleep do macOS, e assim o aviso e a expiração saem no primeiro tick depois de acordar.
- Nos dois casos o teardown (utun, rotas, /32 do gateway, DNS) é imediato, sem logout: na queda o gateway não responde, na expiração ele já encerrou a sessão, e o prazo do logout só atrasaria a volta da rede. Não há reconexão automática.

No contrato v2, essas quedas saem como `{"event":"state","state":"disconnected","reason":"...","cause":"tunnel-dropped"|"expired"}`. O campo `cause` só aparece quando uma sessão já conectada caiu ou expirou; erro de login e desconexão pedida pelo usuário não o trazem. O aviso é o evento `{"v":2,"type":"event","event":"expiring","expires_at":"<RFC 3339>"}`, emitido uma vez por sessão e não repetido a quem abrir o canal de eventos depois.

## 4. Logout

`GET /remote/logout` com o cookie, no disconnect pedido pelo usuário, com prazo de 2 s (**obs**: o FortiClient chama no fim da sessão). Resposta e erro são ignorados. Queda do túnel e expiração não fazem logout.

## O que ainda não está aqui

SAML embutido (sem `redirect`), echo imediato na troca de rede e no wake, DTLS, `tun`/`websocket` e IPv6.

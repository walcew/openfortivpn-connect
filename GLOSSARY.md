# OpenFortiVpn Connect

Cliente macOS para VPNs FortiGate SSL-VPN, com Engine próprio rodando no Helper.

## Language

**Profile**:
A configuração salva de um gateway VPN: host, porta, método de autenticação e certificados confiáveis.
_Avoid_: Connection, account, server

**Helper**:
O daemon privilegiado que roda como root. É o dono da sessão: hospeda o Engine, cria o túnel, aplica rotas e DNS e desfaz tudo quando a sessão termina. A GUI e a CLI `vpnconnect` são clientes iguais do socket dele.
_Avoid_: Daemon, service, agent

**Engine**:
A implementação de um protocolo de VPN dentro do Helper: faz o login e o túnel e entrega a configuração à camada de rede. Hoje só existe o Fortinet SSL VPN.
_Avoid_: Motor externo, backend, driver

**Auto-trust**:
Opção do Profile que aceita qualquer certificado do gateway, só do host daquele Profile, registrando no log as trocas de digest entre conexões. No código, `ignore_cert_errors`.
_Avoid_: Ignorar certificado, insecure, skip verify

**OTP**:
Código de uso único que o usuário digita para concluir o segundo fator de um Profile com senha.
_Avoid_: Token, 2FA code, TOTP code

**FortiToken push**:
Segundo fator em que o gateway envia uma notificação ao celular do usuário, que a aprova sem digitar nenhum OTP.
_Avoid_: Push token, push OTP

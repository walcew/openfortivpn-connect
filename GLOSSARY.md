# OpenFortiVpn Connect

Cliente macOS para VPNs FortiGate SSL-VPN, que usa o openfortivpn como motor de túnel.

## Language

**Profile**:
A configuração salva de um gateway VPN: host, porta, método de autenticação e certificados confiáveis.
_Avoid_: Connection, account, server

**Helper**:
O daemon privilegiado que roda como root e é o único autorizado a iniciar e encerrar o openfortivpn e a alterar rede e DNS.
_Avoid_: Daemon, service, agent

**Bundled openfortivpn**:
O binário do openfortivpn que acompanha o app e é instalado junto com o Helper. É o único que o Helper executa.
_Avoid_: CLI, system openfortivpn, Homebrew openfortivpn

**OTP**:
Código de uso único que o usuário digita para concluir o segundo fator de um Profile com senha.
_Avoid_: Token, 2FA code, TOTP code

**FortiToken push**:
Segundo fator em que o gateway envia uma notificação ao celular do usuário, que a aprova sem digitar nenhum OTP.
_Avoid_: Push token, push OTP

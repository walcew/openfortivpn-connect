# Engine Fortinet próprio no Helper substitui o openfortivpn

**Status:** aceito e em vigor desde a 0.4.0. Substitui o [ADR 0001](0001-bundled-openfortivpn.md).

O app depende do openfortivpn, um processo externo que o Helper dispara e só acompanha até o túnel subir. Sessão expirada vira túnel morto, o disconnect não limpa o que o pppd deixou e a senha vai na linha de comando. Decidimos escrever um **Engine** Fortinet SSL VPN em Rust, dentro do Helper, e substituir o openfortivpn de vez.

- **O Engine roda no Helper root, num único processo.** O Helper é o dono da sessão: faz o login, abre o túnel, cria a interface, aplica rotas e DNS, vigia o túnel e desfaz tudo quando a sessão termina. O estado da sessão deixa de viver na GUI.
- **GUI e CLI são clientes do socket do Helper.** Mandam comandos e recebem eventos pelo protocolo v2 (JSON por linha, com versão). Credenciais vão no corpo da mensagem, nunca em argv. O Helper só aceita root e o usuário do console.
- **utun, sem pppd.** O Helper cria a interface `utun` e fala PPP em modo usuário (LCP e IPCP). Fechar o descritor remove a interface e as rotas dela, o que elimina a limpeza heurística de `pppd` e `ppp*`.
- **Implementação limpa, sob MIT.** openfortivpn (GPL-3.0) e openconnect (LGPL-2.1) servem só como referência do protocolo, sem copiar nem traduzir código. O protocolo fica documentado no repositório.
- **Sem trait de Engine por enquanto.** A fronteira entre o Engine e a camada de rede (utun, rotas, DNS, estado) usa tipos concretos. A abstração só entra quando existir um segundo Engine, como Check Point ou OpenVPN.

## Considered Options

- **Manter o openfortivpn e corrigir os sintomas**: o Helper continuaria sem ver o túnel depois que o processo sobe, a limpeza seguiria heurística e o app ficaria preso a um binário GPL específico.
- **Usar o openconnect (`--protocol=fortinet`)**: resolve parte dos problemas, mas continua sendo um processo externo, LGPL, e não dá ao Helper o controle da sessão.
- **Portar código do openfortivpn ou do openconnect**: traria a licença deles para o projeto. Descartado em favor de implementação limpa.

## Consequences

- O Helper ganha rustls, tokio e o protocolo PPP para manter. O escopo do MVP exclui DTLS, IPv6, os métodos `tun`/`websocket` e a reconexão automática.
- Na 0.4.0 saíram o binário do openfortivpn, o build dele no CI e a licença GPL do bundle. O protocolo antigo do socket (`spawn-vpn`, `kill-vpn`, `setup-dns`, `teardown-dns`) foi removido, e o socket e o label do launchd ganharam nomes neutros (`com.vpnconnect.helper`).
- Instalações existentes reinstalam o Helper uma vez (senha de admin): o instalador da 0.4.0 remove o Helper antigo (label, binário, plist, socket e log) e o openfortivpn bundlado no mesmo passo.

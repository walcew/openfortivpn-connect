# OpenFortiVpn Connect

Cliente macOS para VPNs FortiGate SSL-VPN. A GUI (Tauri 2, React) e a CLI `vpnconnect` são clientes iguais do Helper, o daemon root que hospeda o Engine Fortinet próprio. A CLI é um modo do mesmo executável: com argumentos roda a CLI, sem argumentos abre a GUI.

## Testes e build

- Toolchain: rustup. Rode com `PATH=$HOME/.cargo/bin:$PATH`; o cargo do Homebrew quebra o `tauri-build`.
- Testes: `cd src-tauri && cargo test --workspace`. Os e2e da CLI rodam o executável de debug com `VPNCONNECT_TEST_HOME` (só vale em debug) diante de um Helper falso.
- Build do front: `npm run build` na raiz. O `prebuild` compila o Helper.
- Num build limpo, rode `cd src-tauri && cargo build --release -p openvpngui-helper` antes do `cargo test` ou do `cargo build`: o `tauri.conf.json` empacota `target/release/openvpngui-helper` e o `tauri-build` falha sem ele.

## Onde ler

- `GLOSSARY.md`: a linguagem do domínio (Profile, Helper, Engine, CLI). Use esses termos no código, nos testes e nos commits.
- `docs/adr/`: decisões de arquitetura. Leia antes de mexer na área que cada uma cobre.
- `docs/fortinet-protocol.md`: o protocolo Fortinet que o Engine fala.

## CLI em paridade com a GUI (OBRIGATÓRIO)

Uma feature da GUI só está pronta quando a CLI a cobre. Toda feature que mexe em Profiles, sessão, settings ou Helper entrega, no mesmo PR:

1. o comando em `src-tauri/src/cli/`, com a flag `--json` e o help em `args.rs` explicando como as flags se combinam;
2. o código de saída e o `code` de cada erro novo na tabela de `src-tauri/src/cli/output.rs`;
3. o teste e2e em `src-tauri/tests/cli.rs`;
4. a skill atualizada em `src-tauri/src/cli/skill/SKILL.md`: o comando, o que é decisão humana e os códigos de erro novos.

Fica de fora da CLI só o que existe por ser janela: tray, notificações nativas e preferências visuais. `src-tauri/tests/skill.rs` falha se a skill citar comando ou flag que não existe, ou esquecer um código da tabela de saída.

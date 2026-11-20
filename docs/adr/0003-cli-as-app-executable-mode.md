# CLI como modo do executável do app

**Status:** aceito, desde a CLI `vpnconnect` (spec #33).

A CLI `vpnconnect` precisa ler as senhas dos Profiles no login keychain sem o diálogo de permissão do macOS. Os itens (service `com.openvpngui.app`, account `vpn-<id>`) ficam com a ACL do binário que os gravou, e o app é assinado ad-hoc. Para o macOS, um binário separado seria outro programa, e a assinatura ad-hoc muda a cada build. Ele cairia no diálogo a cada versão, e um agente ou script travaria esperando um clique. Decidimos que a **CLI é um modo do próprio executável do app** (`Contents/MacOS/openvpngui`).

- **Com argumentos, é a CLI; sem argumentos, é a GUI.** O `main` decide antes de qualquer inicialização do Tauri: `cli::wants_cli()` olha só o argv. O `-psn_…` que versões antigas do macOS passavam ao abrir o app pelo Finder não conta como argumento.
- **Sem crate novo, launcher ou entitlement.** A CLI mora em `src-tauri/src/cli/` e reusa os módulos do app (`profile_store`, `settings_store`, `keychain`, `helper_client`). O cliente do Helper não depende do Tauri. A GUI usa uma camada fina por cima dele (`gui_events`), que repassa os eventos ao front, à tray e às notificações.
- **O nome `vpnconnect` vem do cask.** A stanza `binary` aponta para o executável dentro do `.app`, com target `vpnconnect`. CLI e app saem sempre na mesma versão e na mesma release.
- **O Profile do `status` vem do Helper.** Como a GUI, a CLI acha o Profile da sessão pelo `profile_id` dos estados de uma sessão ativa (`connecting`, `waiting-saml`, `waiting-push`, `connected`) e busca o nome nos Profiles locais. O `disconnected` não traz `profile_id`, então `profile` é `null`. Um `profile_id` que não existe mais neste Mac sai com `name: null`. O protocolo v2 não muda.

## Considered Options

- **Binário `vpnconnect` separado, no mesmo bundle**: cai no diálogo do Keychain a cada versão (ACL por binário, assinatura ad-hoc). Também exigiria manter o mesmo código em dois alvos.
- **A CLI pede a senha à GUI por IPC**: obriga a GUI a estar aberta e cria um segundo protocolo, além do socket do Helper.
- **Guardar a senha fora do Keychain para a CLI**: pior em segurança e diverge da GUI.
- **Assinar com Developer ID e usar um keychain access group**: resolveria a ACL, mas exige conta paga e entitlement, e o projeto distribui ad-hoc.

## Consequences

- **Efeito colateral no macOS verificado: nenhum.** Rodar o executável de dentro do `.app` pelo terminal (`.../Contents/MacOS/openvpngui status`, build de debug assinado ad-hoc, macOS 27.2) não registrou o processo no LaunchServices (`lsappinfo find pid=` vazio), não pôs ícone no Dock, não abriu janela e não ativou o app. O mesmo vale pelo symlink `vpnconnect`. Sem argumentos, o executável abre a GUI e se registra como app `Foreground`, como antes. O motivo é que só o Tauri cria o `NSApplication`, e o modo CLI sai antes dele. O que vale para o Dock é quem inicializa o AppKit, não o fato de o binário estar no bundle.
- A CLI só funciona para root e o usuário logado no console, a regra de uid do Helper. Por SSH, sem console, o Helper recusa e a CLI sai com `HELPER_UNAUTHORIZED` (255).
- O binário da CLI carrega o Tauri e o WebKit linkados, então é tão grande quanto o app. O custo de inicialização fica no carregamento dinâmico, sem janela nem runtime.
- Testes de ponta a ponta usam `VPNCONNECT_TEST_HOME`, que só existe no build de debug (`cfg(debug_assertions)`). Ele troca o diretório de config, o Keychain (por arquivos em `keychain/`) e o socket do Helper (`helper.sock`) pelos de um diretório temporário. O binário release ignora a variável.
- Um comando novo da GUI precisa do comando equivalente na CLI. A regra de paridade vai no `AGENTS.md` (spec #33).

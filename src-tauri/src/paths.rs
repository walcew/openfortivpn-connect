//! Onde o app guarda o que é local: o diretório de config e, nos testes de ponta a ponta,
//! o diretório que substitui config, Keychain e socket do Helper.

use std::path::PathBuf;

/// Só em build de debug: `VPNCONNECT_TEST_HOME` isola os testes de ponta a ponta da CLI.
/// Ele vira o diretório de config (`profiles.json`, `settings.json`), troca o Keychain por
/// arquivos em `keychain/` (o Keychain de um binário de teste abre diálogo e trava o teste) e
/// põe o socket do Helper em `helper.sock`. O binário release ignora a variável.
pub fn test_home() -> Option<PathBuf> {
    #[cfg(debug_assertions)]
    return std::env::var_os("VPNCONNECT_TEST_HOME").map(PathBuf::from);
    #[cfg(not(debug_assertions))]
    None
}

/// Diretório de config do app, criado se faltar.
pub fn app_dir() -> Result<PathBuf, String> {
    let dir = match test_home() {
        Some(home) => home,
        None => dirs::config_dir()
            .ok_or_else(|| "Could not determine config directory".to_string())?
            .join("com.openvpngui.app"),
    };
    std::fs::create_dir_all(&dir).map_err(|e| format!("Failed to create app dir: {}", e))?;
    Ok(dir)
}

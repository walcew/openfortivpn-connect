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

/// Grava em um temporário no mesmo diretório e renomeia por cima do destino, para um crash no
/// meio da escrita nunca deixar o arquivo truncado.
pub fn write_atomic(path: &std::path::Path, data: &str) -> std::io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".{}.tmp", std::process::id()));
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, data)
        .and_then(|_| std::fs::rename(&tmp, path))
        .inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp);
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_atomic_replaces_content_and_leaves_no_temp_file() {
        let dir = std::env::temp_dir().join(format!("openvpngui-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("data.json");
        write_atomic(&path, "{\"a\":1}").unwrap();
        write_atomic(&path, "{\"a\":2}").unwrap();
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["a"], 2);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }
}

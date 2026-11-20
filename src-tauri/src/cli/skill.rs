//! `vpnconnect skill` e `skill install`: a skill de orientação do agente de IA, embutida no
//! binário. A cópia canônica fica em `~/.agents/skills`, que os agentes "universais" já leem;
//! os demais, quando instalados (a pasta deles existe), ganham um link para ela. Mesma lógica
//! do `nuvemteam skill install`.

use std::path::{Path, PathBuf};

use serde_json::json;

use super::{CliError, Out};

/// A skill da versão instalada da CLI.
const SKILL: &str = include_str!("skill/SKILL.md");
const NAME: &str = "vpnconnect";

/// O Markdown cru; com `--json`, `{"name","content"}` para o agente não ter de separar nada.
pub fn print(out: &Out) {
    out.emit(&json!({ "name": NAME, "content": SKILL }), || print!("{SKILL}"));
}

pub fn install(out: &Out) -> Result<(), CliError> {
    let home = std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| CliError::failure("CLI_ERROR", "HOME is not set"))?;
    let canonical = home.join(".agents").join("skills").join(NAME);
    let mut installed = vec![("universal", canonical.clone())];
    write_skill(&canonical).map_err(|e| io_error(&canonical, e))?;
    for (agent, present, skills) in linked_agents(&home) {
        if !present.is_dir() {
            continue;
        }
        let dest = skills.join(NAME);
        link(&canonical, &dest).map_err(|e| io_error(&dest, e))?;
        installed.push((agent, dest));
    }
    let list: Vec<_> = installed.iter().map(|(agent, path)| json!({"agent": agent, "path": path})).collect();
    out.emit(&json!({ "installed": list }), || {
        for (agent, path) in &installed {
            println!("{agent}: {}", path.display());
        }
        println!("Run `vpnconnect skill install` again after updating the app.");
    });
    Ok(())
}

/// Os agentes que não leem `~/.agents/skills`: o nome, a pasta cuja existência diz que ele está
/// instalado e a pasta de skills dele.
fn linked_agents(home: &Path) -> [(&'static str, PathBuf, PathBuf); 4] {
    let env_dir = |var: &str, default: PathBuf| {
        std::env::var_os(var).filter(|v| !v.is_empty()).map(PathBuf::from).unwrap_or(default)
    };
    let claude = env_dir("CLAUDE_CONFIG_DIR", home.join(".claude"));
    let goose = env_dir("XDG_CONFIG_HOME", home.join(".config")).join("goose");
    let windsurf = home.join(".codeium").join("windsurf");
    let kiro = home.join(".kiro");
    [
        ("Claude Code", claude.clone(), claude.join("skills")),
        ("Windsurf", windsurf.clone(), windsurf.join("skills")),
        ("Goose", goose.clone(), goose.join("skills")),
        ("Kiro", kiro.clone(), kiro.join("skills")),
    ]
}

/// Liga `dest` à cópia canônica. Uma pasta de verdade já no lugar (instalação manual antiga) é
/// atualizada por cópia.
fn link(canonical: &Path, dest: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dest.parent().unwrap_or(dest))?;
    if dest.is_symlink() {
        std::fs::remove_file(dest)?;
    }
    if dest.exists() {
        return write_skill(dest);
    }
    std::os::unix::fs::symlink(canonical, dest)
}

fn write_skill(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join("SKILL.md"), SKILL)
}

fn io_error(path: &Path, e: std::io::Error) -> CliError {
    CliError::failure("CLI_ERROR", format!("{}: {e}", path.display()))
}

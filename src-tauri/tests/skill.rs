//! A skill embutida: `skill` imprime o `SKILL.md`, `skill install` o grava em `~/.agents/skills`
//! e liga só os agentes cujas pastas existem (com o `HOME` num diretório temporário), e o texto
//! da skill não deriva da CLI: todo código da tabela de saída e todo comando citado existem.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_openvpngui");
const SKILL: &str = include_str!("../src/cli/skill/SKILL.md");
const OUTPUT_RS: &str = include_str!("../src/cli/output.rs");

/// Um HOME temporário, apagado no fim.
struct Home(PathBuf);

impl Home {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("vpns-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn run(&self, env: &[(&str, &Path)], args: &[&str]) -> Output {
        let mut cmd = Command::new(BIN);
        cmd.args(args).env("HOME", &self.0).env_remove("CLAUDE_CONFIG_DIR").env_remove("XDG_CONFIG_HOME");
        for (key, value) in env {
            cmd.env(key, value);
        }
        cmd.output().unwrap()
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn assert_installed(dir: &Path) {
    assert_eq!(std::fs::read_to_string(dir.join("SKILL.md")).unwrap(), SKILL, "{}", dir.display());
}

#[test]
fn skill_prints_the_embedded_file() {
    let out = Home::new().run(&[], &["skill"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), SKILL);
    assert!(SKILL.starts_with("---\nname: vpnconnect\n"));
}

#[test]
fn skill_json_wraps_the_markdown_and_nothing_else() {
    let out = Home::new().run(&[], &["skill", "--json"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let v: serde_json::Value = serde_json::from_str(text(&out.stdout).trim()).unwrap();
    assert_eq!(v["name"], "vpnconnect");
    assert_eq!(v["content"], SKILL);
}

#[test]
fn install_writes_the_canonical_copy_and_links_only_present_agents() {
    let home = Home::new();
    std::fs::create_dir_all(home.0.join(".claude")).unwrap();
    std::fs::create_dir_all(home.0.join(".kiro")).unwrap();

    let out = home.run(&[], &["skill", "install"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));

    for dir in [".agents/skills/vpnconnect", ".claude/skills/vpnconnect", ".kiro/skills/vpnconnect"] {
        assert_installed(&home.0.join(dir));
    }
    assert!(home.0.join(".claude/skills/vpnconnect").is_symlink());
    assert!(!home.0.join(".codeium").exists());
    assert!(!home.0.join(".config").exists());

    // Idempotente: rodar de novo termina igual.
    let again = home.run(&[], &["skill", "install"]);
    assert_eq!(again.status.code(), Some(0), "{}", text(&again.stderr));
    assert_eq!(text(&again.stdout), text(&out.stdout));
    assert_installed(&home.0.join(".claude/skills/vpnconnect"));
}

#[test]
fn install_follows_claude_config_dir() {
    let home = Home::new();
    let claude = home.0.join("custom-claude");
    std::fs::create_dir_all(&claude).unwrap();
    // A pasta padrão também existe, mas o `CLAUDE_CONFIG_DIR` manda.
    std::fs::create_dir_all(home.0.join(".claude")).unwrap();

    let out = home.run(&[("CLAUDE_CONFIG_DIR", &claude)], &["skill", "install"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));

    assert_installed(&claude.join("skills/vpnconnect"));
    assert!(!home.0.join(".claude/skills").exists());
}

#[test]
fn install_without_agent_folders_writes_only_the_canonical_copy() {
    let home = Home::new();
    let out = home.run(&[], &["skill", "install", "--json"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let json: serde_json::Value = serde_json::from_str(&text(&out.stdout)).unwrap();
    assert_eq!(json["installed"].as_array().unwrap().len(), 1);
    assert_installed(&home.0.join(".agents/skills/vpnconnect"));
    assert!(!home.0.join(".claude").exists());
}

/// Os códigos da tabela de saída do `output.rs`: os nomes em maiúsculas entre crases.
fn table_codes() -> Vec<&'static str> {
    OUTPUT_RS
        .lines()
        .filter(|l| l.starts_with("//! |"))
        .flat_map(|l| l.split('`').skip(1).step_by(2))
        .filter(|w| w.len() > 3 && w.chars().all(|c| c.is_ascii_uppercase() || c == '_'))
        .collect()
}

#[test]
fn every_exit_code_of_the_output_table_is_in_the_skill() {
    let codes = table_codes();
    assert!(codes.len() > 20, "only {} codes parsed", codes.len());
    for code in codes {
        assert!(SKILL.contains(&format!("`{code}`")), "{code} is not in the skill");
    }
}

/// Os blocos de código e os trechos entre crases do `SKILL.md`.
fn code_spans() -> Vec<&'static str> {
    let mut spans = Vec::new();
    let mut in_block = false;
    for line in SKILL.lines() {
        if line.starts_with("```") {
            in_block = !in_block;
        } else if in_block {
            spans.push(line);
        } else {
            spans.extend(line.split('`').skip(1).step_by(2));
        }
    }
    spans
}

/// Cada `vpnconnect <comando>` da skill existe, e cada `--opção` da mesma linha consta no help.
#[test]
fn every_command_and_flag_in_the_skill_exists() {
    let home = Home::new();
    let mut checked = 0;
    for span in code_spans() {
        let Some(at) = span.find("vpnconnect ") else { continue };
        let mut words = span[at..].split_whitespace().skip(1).skip_while(|w| *w == "--json");
        let mut path: Vec<&str> = Vec::new();
        for w in words.by_ref() {
            let nested = path == ["settings", "set"];
            let is_name = w.chars().all(|c| c.is_ascii_lowercase() || c == '-') && !w.starts_with("--");
            if is_name && (path.len() < 2 || nested) {
                path.push(w);
            } else {
                break;
            }
        }
        if path.is_empty() {
            continue;
        }
        let help = home.run(&[], &[&path[..], &["--help"]].concat());
        assert_eq!(help.status.code(), Some(0), "`{span}`: {}", text(&help.stderr));
        let help = text(&help.stdout);
        for flag in span.split(|c: char| !(c.is_ascii_lowercase() || c == '-')).filter(|w| w.len() > 2 && w.starts_with("--")) {
            assert!(help.contains(flag), "`{span}`: {flag} is not in `{}` help", path.join(" "));
        }
        checked += 1;
    }
    assert!(checked > 15, "only {checked} commands checked");
}

#[test]
fn every_command_of_the_cli_is_in_the_skill() {
    for command in [
        "status", "connect", "disconnect", "watch", "profile ls", "profile show", "profile add", "profile edit", "profile rm",
        "profile set-password", "profile clear-password", "profile trust", "profile untrust", "settings show",
        "settings set dns-fallback", "helper status", "helper install", "helper uninstall", "skill install",
    ] {
        assert!(SKILL.contains(&format!("vpnconnect {command}")), "`vpnconnect {command}` is not in the skill");
    }
}

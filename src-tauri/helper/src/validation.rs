/// Validate that a string is a valid IPv4 address.
pub fn is_valid_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok())
}

/// Validate that a string is a plausible hostname (letters, digits, dots, hyphens).
pub fn is_valid_hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && !s.starts_with('-')
        && !s.starts_with('.')
}

/// Validate a log file path — must be under /tmp/ and not contain path traversal.
pub fn is_valid_log_path(s: &str) -> bool {
    s.starts_with("/tmp/openvpngui-") && !s.contains("..")
}

/// Check that a process with the given PID is actually openfortivpn.
/// Returns true if the PID exists and its command name contains "openfortivpn".
pub fn is_openfortivpn_pid(pid: u32) -> bool {
    let output = std::process::Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "comm="])
        .output();
    match output {
        Ok(o) => {
            let comm = String::from_utf8_lossy(&o.stdout);
            comm.trim().contains("openfortivpn")
        }
        Err(_) => false,
    }
}

/// Validate that a gateway is a valid IPv4 address.
pub fn is_valid_gateway(s: &str) -> bool {
    is_valid_ipv4(s)
}

/// Opções longas do openfortivpn v1.24.1 que executam programa ou leem/escrevem
/// arquivo arbitrário como root. "plugin" não existe na v1.24.1; fica por cautela.
const BLOCKED_LONG_OPTIONS: &[&str] = &[
    "config",       // config arbitrário, que pode conter pppd-plugin/pinentry
    "pinentry",     // executa um programa
    "pppd-log",     // pppd grava onde quiser
    "pppd-plugin",  // pppd carrega um plugin
    "pppd-call",    // pppd lê /etc/ppp/peers/<name>
    "pppd-ifname",
    "plugin",
];

/// Opções longas do openfortivpn v1.24.1 (src/main.c) com valor obrigatório, que
/// aceitam `--opt valor`. Servem para pular o valor: uma senha "-cabc" depois de
/// `-p` não é a opção `-c`.
const LONG_OPTIONS_WITH_VALUE: &[&str] = &[
    "config", "pinentry", "realm", "username", "password", "cookie", "otp",
    "otp-prompt", "otp-delay", "ifname", "set-routes", "sni", "half-internet-routes",
    "set-dns", "persistent", "ca-file", "user-cert", "user-key", "pem-passphrase",
    "trusted-cert", "cipher-list", "min-tls", "pppd-use-peerdns", "pppd-log",
    "pppd-plugin", "pppd-ipparam", "pppd-ifname", "pppd-call",
];
const LONG_OPTIONS_WITHOUT_VALUE: &[&str] = &[
    "help", "version", "cookie-on-stdin", "saml-login", "no-ftm-push", "no-routes",
    "no-dns", "use-syslog", "insecure-ssl", "seclevel-1", "pppd-no-peerdns",
    "pppd-accept-remote",
];

/// Resolve `name` como o getopt_long: nome exato ou prefixo único. Ambíguo ou
/// desconhecido devolve false; o openfortivpn recusa esses e sai.
fn takes_separate_value(name: &str) -> bool {
    if LONG_OPTIONS_WITH_VALUE.contains(&name) {
        return true;
    }
    if LONG_OPTIONS_WITHOUT_VALUE.contains(&name) {
        return false;
    }
    let mut candidates = LONG_OPTIONS_WITH_VALUE
        .iter()
        .chain(LONG_OPTIONS_WITHOUT_VALUE)
        .filter(|o| o.starts_with(name));
    match (candidates.next(), candidates.next()) {
        (Some(o), None) => LONG_OPTIONS_WITH_VALUE.contains(o),
        _ => false,
    }
}

/// Rejeita argumentos que fariam o openfortivpn/pppd (root) executar código ou
/// escrever arquivo arbitrário. Lista de bloqueio, não de permissão: os Profiles
/// têm extra_args livres. Cobre `--opt=valor`, `--opt valor`, abreviações que o
/// getopt_long aceita (`--conf`), `-c` e `-c` agrupado (`-vc arq`, `-carq`).
pub fn validate_vpn_args(args: &[String]) -> Result<(), String> {
    let blocked = |arg: &String| Err(format!("Blocked argument: {}", arg));
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        let lower = arg.to_lowercase();
        let mut skip_value = false;
        if let Some(long) = lower.strip_prefix("--") {
            let (name, inline_value) = match long.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (long, None),
            };
            if !name.is_empty() {
                // Conservador: bloqueia também prefixos ambíguos e nomes estendidos.
                let matches = |opt: &str| opt.starts_with(name) || name.starts_with(opt);
                if BLOCKED_LONG_OPTIONS.iter().any(|o| matches(o)) {
                    return blocked(arg);
                }
                // pkcs11: o OpenSSL carrega um engine dinâmico do ENGINESDIR do build.
                if matches("user-cert") {
                    let value = inline_value.or(args.get(i + 1).map(|v| v.as_str()));
                    if value.is_some_and(|v| v.to_lowercase().starts_with("pkcs11")) {
                        return blocked(arg);
                    }
                }
                skip_value = inline_value.is_none() && takes_separate_value(name);
            }
        } else if let Some(shorts) = arg.strip_prefix('-') {
            // Opções curtas agrupadas (getopt "hvqc:u:p:o:"): u, p e o consomem
            // o resto como valor ou, se nada sobra, o próximo argumento.
            for (pos, c) in shorts.char_indices() {
                match c {
                    'c' => return blocked(arg),
                    'u' | 'p' | 'o' => {
                        skip_value = pos + 1 == shorts.len();
                        break;
                    }
                    _ => {}
                }
            }
        }
        i += if skip_value { 2 } else { 1 };
    }
    Ok(())
}

/// Único binário que o Helper executa: o Bundled openfortivpn, instalado como
/// root pelo app. Sem fallback para o Homebrew (ver ADR 0001). Par de
/// OPENFORTIVPN_INSTALL_PATH em src-tauri/src/helper_installer.rs.
pub const OPENFORTIVPN_PATH: &str = "/Library/PrivilegedHelperTools/openfortivpn";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_ipv4() {
        assert!(is_valid_ipv4("10.0.0.1"));
        assert!(is_valid_ipv4("192.168.1.1"));
        assert!(is_valid_ipv4("0.0.0.0"));
        assert!(is_valid_ipv4("255.255.255.255"));
    }

    #[test]
    fn test_invalid_ipv4() {
        assert!(!is_valid_ipv4("256.0.0.1"));
        assert!(!is_valid_ipv4("10.0.0"));
        assert!(!is_valid_ipv4("10.0.0.1.2"));
        assert!(!is_valid_ipv4("abc.def.ghi.jkl"));
        assert!(!is_valid_ipv4(""));
    }

    #[test]
    fn test_valid_hostname() {
        assert!(is_valid_hostname("corp.example.com"));
        assert!(is_valid_hostname("my-domain.co"));
        assert!(is_valid_hostname("a"));
    }

    #[test]
    fn test_invalid_hostname() {
        assert!(!is_valid_hostname(""));
        assert!(!is_valid_hostname("-start.com"));
        assert!(!is_valid_hostname(".start.com"));
        assert!(!is_valid_hostname("bad domain.com"));
        assert!(!is_valid_hostname("bad;domain.com"));
    }

    #[test]
    fn test_valid_log_path() {
        assert!(is_valid_log_path("/tmp/openvpngui-abc123.log"));
        assert!(is_valid_log_path(
            "/tmp/openvpngui-550e8400-e29b-41d4-a716-446655440000.log"
        ));
    }

    #[test]
    fn test_invalid_log_path() {
        assert!(!is_valid_log_path("/etc/passwd"));
        assert!(!is_valid_log_path("/tmp/other-file.log"));
        assert!(!is_valid_log_path("/tmp/openvpngui-../../etc/passwd"));
    }

    #[test]
    fn test_validate_vpn_args() {
        assert!(validate_vpn_args(&vec![
            "-u".to_string(), "user".to_string(),
            "-p".to_string(), "pass".to_string(),
            "--trusted-cert=abc".to_string(),
        ]).is_ok());
    }

    #[test]
    fn test_validate_vpn_args_rejects_dangerous() {
        assert!(validate_vpn_args(&vec![
            "--pppd-plugin=/evil".to_string(),
        ]).is_err());
        assert!(validate_vpn_args(&vec![
            "--plugin=/evil".to_string(),
        ]).is_err());
    }

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn rejects_new_blocked_options_in_both_forms() {
        for opt in ["config", "pinentry", "pppd-log", "pppd-call", "pppd-ifname"] {
            let eq = format!("--{}=/tmp/x", opt);
            let flag = format!("--{}", opt);
            assert!(validate_vpn_args(&args(&[&eq])).is_err(), "{}", eq);
            assert!(validate_vpn_args(&args(&[&flag, "/tmp/x"])).is_err(), "{}", flag);
        }
    }

    #[test]
    fn rejects_long_option_abbreviations() {
        for a in ["--conf=/tmp/x", "--pinent=/tmp/evil", "--pppd-lo=/etc/x", "--CONFIG=/x"] {
            assert!(validate_vpn_args(&args(&[a])).is_err(), "{}", a);
        }
    }

    #[test]
    fn rejects_short_config_option() {
        assert!(validate_vpn_args(&args(&["-c", "/tmp/x"])).is_err());
        assert!(validate_vpn_args(&args(&["-c/tmp/x"])).is_err());
        assert!(validate_vpn_args(&args(&["-vc", "/tmp/x"])).is_err());
    }

    #[test]
    fn short_option_values_are_not_mistaken_for_config() {
        assert!(validate_vpn_args(&args(&["-pabc", "-ucarl", "-o", "c123", "-vvq"])).is_ok());
    }

    #[test]
    fn rejects_pkcs11_user_cert_in_both_forms() {
        assert!(validate_vpn_args(&args(&["--user-cert=pkcs11:token=x"])).is_err());
        assert!(validate_vpn_args(&args(&["--user-cert", "pkcs11:token=x"])).is_err());
        assert!(validate_vpn_args(&args(&["--user-cert=/tmp/cert.pem"])).is_ok());
        assert!(validate_vpn_args(&args(&["--user-cert", "/tmp/cert.pem"])).is_ok());
    }

    #[test]
    fn separate_option_values_are_not_parsed_as_options() {
        assert!(validate_vpn_args(&args(&[
            "-u", "-cuser", "-p", "--config=x", "--otp", "-c", "--pass", "--pinentry",
        ])).is_ok());
    }

    #[test]
    fn flags_without_value_do_not_hide_the_next_argument() {
        assert!(validate_vpn_args(&args(&["--use-syslog", "-c", "/tmp/x"])).is_err());
        assert!(validate_vpn_args(&args(&["-v", "--pinentry=/x"])).is_err());
        // Prefixo ambíguo (--co: config, cookie...) não pula o próximo argumento.
        assert!(validate_vpn_args(&args(&["--cook", "x", "-c", "/tmp/x"])).is_err());
    }

    #[test]
    fn allows_common_extra_args() {
        assert!(validate_vpn_args(&args(&[
            "--cookie=abc", "--persistent=5", "--pppd-use-peerdns=1", "--pppd-ipparam=x",
            "--set-dns=0", "--trusted-cert=abc", "--realm=r", "--", "host:443",
        ])).is_ok());
    }
}

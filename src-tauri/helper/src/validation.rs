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

/// The only binary we allow the helper to execute.
pub const OPENFORTIVPN_PATH: &str = "/opt/homebrew/bin/openfortivpn";

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
}

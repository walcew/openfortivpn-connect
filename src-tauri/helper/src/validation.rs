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
}

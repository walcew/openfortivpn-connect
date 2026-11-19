use std::process::Command;

/// Capture the current DNS servers configured on the system (from DHCP/manual).
/// Parses `scutil --dns` output to find the primary resolver's nameservers.
pub fn get_current_dns_servers() -> Vec<String> {
    let output = match Command::new("scutil").args(["--dns"]).output() {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut servers = Vec::new();
    let mut in_first_resolver = false;

    for line in stdout.lines() {
        let trimmed = line.trim();
        // Only parse the first resolver block (primary DHCP resolver)
        if trimmed.starts_with("resolver #1") {
            in_first_resolver = true;
            continue;
        }
        if in_first_resolver && trimmed.starts_with("resolver #") {
            break;
        }
        if in_first_resolver && trimmed.starts_with("nameserver[") {
            // Format: "nameserver[0] : 1.1.1.1"
            if let Some(ip) = trimmed.split(':').nth(1) {
                let ip = ip.trim();
                let parts: Vec<&str> = ip.split('.').collect();
                if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
                    if !servers.contains(&ip.to_string()) {
                        servers.push(ip.to_string());
                    }
                }
            }
        }
    }

    log::info!("Current system DNS servers: {:?}", servers);
    servers
}

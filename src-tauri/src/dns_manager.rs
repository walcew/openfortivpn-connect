use std::process::Command;

/// Configure macOS DNS via scutil for the VPN interface.
/// This is necessary because macOS ignores /etc/resolv.conf and uses
/// the SystemConfiguration framework instead. openfortivpn only writes
/// to resolv.conf, which doesn't affect macOS DNS resolution.
pub fn setup_dns(dns_servers: &[String], dns_suffix: Option<&str>) -> Result<(), String> {
    if dns_servers.is_empty() {
        return Ok(());
    }

    // Build scutil commands to create a resolver for the VPN
    let mut scutil_commands = String::new();
    scutil_commands.push_str("d.init\n");
    for (i, server) in dns_servers.iter().enumerate() {
        scutil_commands.push_str(&format!("d.add ServerAddresses * {}\n", server));
        if i == 0 {
            // First add sets the array, subsequent ones should append
            // Actually scutil d.add with * creates an array, let's build it properly
        }
    }

    // Build the full server list as a single d.add command
    let servers_str = dns_servers.join(" ");

    let domain_line = if let Some(suffix) = dns_suffix {
        format!("d.add DomainName {}\n", suffix)
    } else {
        String::new()
    };

    let scutil_input = format!(
        "d.init\n\
         d.add ServerAddresses * {servers}\n\
         {domain}\
         d.add SupplementalMatchDomains * \"\"\n\
         set State:/Network/Service/OpenFortiVPN/DNS\n\
         quit\n",
        servers = servers_str,
        domain = domain_line,
    );

    log::info!("Setting up macOS DNS via scutil with servers: {}", servers_str);

    let output = Command::new("osascript")
        .args([
            "-e",
            &format!(
                "do shell script \"echo '{}' | /usr/sbin/scutil\" with administrator privileges",
                applescript_escape_inner(&scutil_input)
            ),
        ])
        .output()
        .map_err(|e| format!("Failed to configure DNS: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("scutil DNS setup failed: {}", stderr));
    }

    log::info!("macOS DNS configured successfully");
    Ok(())
}

/// Remove the VPN DNS configuration from macOS
pub fn teardown_dns() -> Result<(), String> {
    let scutil_input = "remove State:/Network/Service/OpenFortiVPN/DNS\nquit\n";

    log::info!("Tearing down macOS DNS configuration");

    let output = Command::new("osascript")
        .args([
            "-e",
            &format!(
                "do shell script \"echo '{}' | /usr/sbin/scutil\" with administrator privileges",
                applescript_escape_inner(scutil_input)
            ),
        ])
        .output()
        .map_err(|e| format!("Failed to teardown DNS: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Don't fail if it's already gone
        if !stderr.contains("User canceled") {
            log::warn!("scutil DNS teardown returned error: {}", stderr);
        }
    }

    log::info!("macOS DNS configuration removed");
    Ok(())
}

/// Parse DNS servers from openfortivpn log output.
/// With -v flag, openfortivpn logs:
///   "Found dns server 10.0.0.1 in xml config"
///   "Found dns suffix corp.example.com in xml config"
pub fn parse_dns_from_log(line: &str) -> Option<DnsInfo> {
    let trimmed = line.trim();

    // Match "Found dns server X.X.X.X in xml config"
    if trimmed.contains("Found dns server") {
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        for (i, part) in parts.iter().enumerate() {
            if *part == "server" && i + 1 < parts.len() {
                let ip = parts[i + 1];
                let octets: Vec<&str> = ip.split('.').collect();
                if octets.len() == 4 && octets.iter().all(|o| o.parse::<u8>().is_ok()) {
                    return Some(DnsInfo::Server(ip.to_string()));
                }
            }
        }
    }

    // Match "Found dns suffix example.com in xml config"
    if trimmed.contains("Found dns suffix") {
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        for (i, part) in parts.iter().enumerate() {
            if *part == "suffix" && i + 1 < parts.len() {
                let domain = parts[i + 1];
                if domain.contains('.') {
                    return Some(DnsInfo::SearchDomain(domain.to_string()));
                }
            }
        }
    }

    None
}

#[derive(Debug, Clone)]
pub enum DnsInfo {
    Server(String),
    SearchDomain(String),
}

/// Escape for use inside a single-quoted AppleScript string that's inside a double-quoted shell string.
/// We need to handle single quotes in the scutil input and also escape for the AppleScript layer.
fn applescript_escape_inner(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\'', "'\\''")
        .replace('\n', "\\n")
}

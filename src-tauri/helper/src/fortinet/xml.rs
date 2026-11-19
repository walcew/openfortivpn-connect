//! Parse da resposta de `/remote/fortisslvpn_xml`.

use std::net::Ipv4Addr;

use crate::net::Route;

#[derive(Debug, Default)]
pub struct XmlConfig {
    pub dns_servers: Vec<Ipv4Addr>,
    pub dns_suffixes: Vec<String>,
    /// Vazio = full tunnel.
    pub routes: Vec<Route>,
    pub mtu: Option<u16>,
    /// Segundos até o fim da sessão.
    pub auth_timeout: Option<u64>,
}

pub fn parse(body: &[u8]) -> Result<XmlConfig, String> {
    let text = std::str::from_utf8(body).map_err(|_| "Tunnel configuration is not UTF-8")?;
    let doc = roxmltree::Document::parse(text).map_err(|e| format!("Invalid tunnel configuration: {}", e))?;
    let mut config = XmlConfig::default();
    for node in doc.descendants().filter(|n| n.is_element()) {
        let attr = |name: &str| node.attribute(name);
        match node.tag_name().name() {
            "dns" => config.dns_servers.extend(attr("ip").and_then(|ip| ip.parse::<Ipv4Addr>().ok())),
            // Mais de um sufixo pode vir separado por ';'.
            "dns-suffix" => config.dns_suffixes.extend(
                attr("str").unwrap_or("").split(';').map(str::trim).filter(|s| !s.is_empty()).map(String::from),
            ),
            "addr" if node.parent_element().is_some_and(|p| p.has_tag_name("split-tunnel-info")) => {
                let route = attr("ip").and_then(|a| a.parse().ok()).zip(attr("mask").and_then(|m| m.parse().ok()));
                match route {
                    Some((addr, mask)) => config.routes.push(Route { addr, mask }),
                    None => return Err("Invalid route in tunnel configuration".into()),
                }
            }
            "mtu" => config.mtu = attr("val").and_then(|v| v.parse().ok()),
            "auth-timeout" => config.auth_timeout = attr("val").and_then(|v| v.parse().ok()).filter(|&s| s > 0),
            _ => {}
        }
    }
    Ok(config)
}

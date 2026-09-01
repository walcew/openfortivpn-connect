use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use sha2::{Digest, Sha256};

const TLS_TIMEOUT: Duration = Duration::from_secs(5);

/// Abre um handshake TLS com o gateway sem validar a cadeia e devolve o sha256
/// do certificado apresentado, no mesmo formato que o openfortivpn espera em
/// `--trusted-cert`.
///
/// O openfortivpn não tem uma opção "ignore certificate": a única forma de
/// aceitar um gateway cujo certificado não valida é informar o digest sha256
/// do certificado. Buscar o digest antes de conectar evita a tentativa que
/// falha e mantém o perfil funcionando quando o certificado é renovado.
pub fn fetch_gateway_digest(host: &str, port: u16) -> Result<String, String> {
    let addr = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("Failed to resolve {}:{}: {}", host, port, e))?
        .next()
        .ok_or_else(|| format!("No address found for {}:{}", host, port))?;

    let stream = TcpStream::connect_timeout(&addr, TLS_TIMEOUT)
        .map_err(|e| format!("Failed to connect to {}:{}: {}", host, port, e))?;
    let _ = stream.set_read_timeout(Some(TLS_TIMEOUT));
    let _ = stream.set_write_timeout(Some(TLS_TIMEOUT));

    let connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .map_err(|e| format!("Failed to build TLS connector: {}", e))?;

    let tls = connector
        .connect(host, stream)
        .map_err(|e| format!("TLS handshake with {}:{} failed: {}", host, port, e))?;

    let cert = tls
        .peer_certificate()
        .map_err(|e| format!("Failed to read gateway certificate: {}", e))?
        .ok_or_else(|| "Gateway did not present a certificate".to_string())?;

    let der = cert
        .to_der()
        .map_err(|e| format!("Failed to encode gateway certificate: {}", e))?;

    Ok(Sha256::digest(&der)
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect())
}


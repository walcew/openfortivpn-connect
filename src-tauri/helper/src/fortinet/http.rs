//! TLS do gateway e o mínimo de HTTP/1.1 que o protocolo usa.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio_rustls::rustls::client::WebPkiServerVerifier;
use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::crypto::{self, CryptoProvider};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};

/// Raízes de confiança e histórico de digests, vivos enquanto o Helper roda.
pub struct Trust {
    /// None usa as raízes do sistema; o teste injeta as suas.
    roots: Option<Arc<RootCertStore>>,
    // shortcut: o histórico de digests vive em memória e se perde quando o Helper reinicia; persistir em disco quando a troca de certificado entre reinícios importar.
    digests: Mutex<HashMap<String, String>>,
}

impl Trust {
    pub fn system() -> Self {
        Self { roots: None, digests: Mutex::default() }
    }

    #[cfg(test)]
    pub fn with_roots(roots: RootCertStore) -> Self {
        Self { roots: Some(Arc::new(roots)), digests: Mutex::default() }
    }

    fn roots_verifier(&self, provider: &Arc<CryptoProvider>) -> Result<Arc<dyn ServerCertVerifier>, String> {
        match &self.roots {
            Some(roots) => Ok(WebPkiServerVerifier::builder_with_provider(roots.clone(), provider.clone())
                .build()
                .map_err(|e| e.to_string())?),
            None => Ok(Arc::new(rustls_platform_verifier::Verifier::new(provider.clone()).map_err(|e| e.to_string())?)),
        }
    }

    /// Guarda o digest do host e devolve o anterior quando ele mudou.
    fn record(&self, host: &str, digest: &str) -> Option<String> {
        let old = self.digests.lock().unwrap().insert(host.to_string(), digest.to_string());
        old.filter(|o| o != digest)
    }
}

/// Ponto único da validação do certificado do gateway. Nasce por conexão e só vê o
/// host do Profile, então o auto-trust não vaza para outro host.
struct GatewayCertVerifier {
    host: String,
    trusted_certs: Vec<String>,
    auto_trust: bool,
    roots: Arc<dyn ServerCertVerifier>,
    trust: Arc<Trust>,
    /// Emite a linha como evento de log da sessão.
    log: Arc<dyn Fn(String) + Send + Sync>,
    provider: Arc<CryptoProvider>,
}

impl std::fmt::Debug for GatewayCertVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayCertVerifier").field("host", &self.host).finish_non_exhaustive()
    }
}

/// sha256 em hex do DER, o mesmo formato de `trusted_certs` no app.
fn digest(cert: &CertificateDer<'_>) -> String {
    Sha256::digest(cert.as_ref()).iter().map(|b| format!("{:02x}", b)).collect()
}

impl ServerCertVerifier for GatewayCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let digest = digest(end_entity);
        if self.auto_trust {
            if let Some(old) = self.trust.record(&self.host, &digest) {
                let line = format!("gateway certificate of {} changed: sha256 {} -> {}", self.host, old, digest);
                log::warn!("{}", line);
                (self.log)(line);
            }
            return Ok(ServerCertVerified::assertion());
        }
        if self.trusted_certs.iter().any(|c| c.eq_ignore_ascii_case(&digest))
            || self.roots.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now).is_ok()
        {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::General(format!("untrusted gateway certificate, sha256 digest {}", digest)))
        }
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

pub fn client_config(
    host: &str,
    trusted_certs: &[String],
    auto_trust: bool,
    trust: &Arc<Trust>,
    log: Arc<dyn Fn(String) + Send + Sync>,
) -> Result<ClientConfig, String> {
    let provider = Arc::new(crypto::ring::default_provider());
    let verifier = GatewayCertVerifier {
        host: host.to_string(),
        trusted_certs: trusted_certs.to_vec(),
        auto_trust,
        roots: trust.roots_verifier(&provider)?,
        trust: trust.clone(),
        log,
        provider: provider.clone(),
    };
    Ok(ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth())
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    /// Valor de um cookie em `Set-Cookie`.
    pub fn cookie(&self, name: &str) -> Option<String> {
        self.headers
            .iter()
            .filter(|(k, _)| k == "set-cookie")
            .filter_map(|(_, v)| v.split(';').next()?.trim().strip_prefix(name)?.strip_prefix('=').map(str::to_string))
            .next()
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
}

/// Lê uma resposta inteira: por `Content-Length`, chunked ou até o EOF.
pub async fn read_response<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Response, String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = match stream.read(&mut chunk).await {
            Ok(n) => n,
            // Gateways costumam fechar sem close_notify.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
            Err(e) => return Err(e.to_string()),
        };
        buf.extend_from_slice(&chunk[..n]);
        if let Some(resp) = parse_response(&buf, n == 0)? {
            return Ok(resp);
        }
        if n == 0 {
            return Err("connection closed before the response ended".into());
        }
    }
}

/// None enquanto a resposta estiver incompleta.
fn parse_response(buf: &[u8], eof: bool) -> Result<Option<Response>, String> {
    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Ok(None);
    };
    let head = String::from_utf8_lossy(&buf[..end]);
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or("invalid HTTP status line")?;
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let mut resp = Response { status, headers, body: Vec::new() };
    let rest = &buf[end + 4..];

    if let Some(len) = resp.header("content-length").and_then(|v| v.parse::<usize>().ok()) {
        if rest.len() < len {
            return Ok(None);
        }
        resp.body = rest[..len].to_vec();
    } else if resp.header("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
        match dechunk(rest) {
            Some(body) => resp.body = body,
            None => return Ok(None),
        }
    } else if eof {
        resp.body = rest.to_vec();
    } else {
        return Ok(None);
    }
    Ok(Some(resp))
}

/// Corpo chunked completo, ou None se ainda faltar o chunk final.
fn dechunk(mut data: &[u8]) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line_end = data.windows(2).position(|w| w == b"\r\n")?;
        let size_text = std::str::from_utf8(&data[..line_end]).ok()?;
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        data = &data[line_end + 2..];
        if size == 0 {
            return Some(body);
        }
        if data.len() < size + 2 {
            return None;
        }
        body.extend_from_slice(&data[..size]);
        data = &data[size + 2..];
    }
}

/// `application/x-www-form-urlencoded` de um valor.
pub fn form_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'*' => (b as char).to_string(),
            b' ' => "+".into(),
            _ => format!("%{:02X}", b),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunked_body_is_decoded_only_when_complete() {
        let full = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n2\r\nef\r\n0\r\n\r\n";
        assert!(parse_response(&full[..full.len() - 7], false).unwrap().is_none());
        assert_eq!(parse_response(full, false).unwrap().unwrap().body, b"abcdef");
    }
}

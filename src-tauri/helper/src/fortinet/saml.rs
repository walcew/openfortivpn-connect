//! Listener local do SAML pelo navegador externo: recebe o `id` que o gateway manda o
//! navegador entregar em `127.0.0.1:<sso_port>`.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

/// Prazo de cada conexão para mandar o cabeçalho; a pré-conexão vazia do navegador cai nele.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REQUEST: usize = 8192;
/// O formato do `id` é **inf**: aceita o que cabe numa query sem escape, com folga no tamanho.
const MAX_ID: usize = 1024;

const DONE_PAGE: &str = "<!doctype html><html><head><meta charset=\"utf-8\"><title>VPN login</title></head>\
<body style=\"font-family:sans-serif;text-align:center;margin-top:4em\">\
<h2>Login complete</h2><p>You can close this tab and return to the app.</p></body></html>";
const INVALID_PAGE: &str = "<!doctype html><html><body><h2>Invalid login response</h2></body></html>";

/// Escuta só em loopback, nunca em 0.0.0.0.
pub async fn listen(port: u16) -> Result<TcpListener, String> {
    TcpListener::bind(("127.0.0.1", port)).await.map_err(|e| match e.kind() {
        std::io::ErrorKind::AddrInUse => format!(
            "Local SSO port {} is already in use; close the app using it (e.g. FortiClient) and try again",
            port
        ),
        _ => format!("Cannot listen on 127.0.0.1:{}: {}", port, e),
    })
}

/// Espera a conexão com `?id=`, responde ao navegador e devolve o `id` validado.
/// Conexões sem `?id=` (o navegador abre algumas vazias antes da real) são ignoradas.
/// O listener fecha quando a função volta.
pub async fn wait_for_id(listener: TcpListener) -> Result<String, String> {
    let (tx, mut rx) = mpsc::channel::<(TcpStream, String)>(4);
    loop {
        tokio::select! {
            Ok((stream, _)) = listener.accept() => {
                let tx = tx.clone();
                tokio::spawn(async move {
                    if let Ok(Some((stream, line))) = tokio::time::timeout(REQUEST_TIMEOUT, read_head(stream)).await {
                        if line.contains("?id=") {
                            let _ = tx.send((stream, line)).await;
                        }
                    }
                });
            }
            Some((mut stream, line)) = rx.recv() => {
                let id = extract_id(&line);
                let (status, page) = if id.is_some() { ("200 OK", DONE_PAGE) } else { ("400 Bad Request", INVALID_PAGE) };
                let resp = format!(
                    "HTTP/1.1 {}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status, page.len(), page
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
                return id.ok_or_else(|| "SAML login failed: invalid SAML id received from the browser".into());
            }
        }
    }
}

/// Lê o cabeçalho inteiro (fechar com dados não lidos faria o navegador ver um reset) e
/// devolve a linha do pedido. None em conexão vazia, grande demais ou sem texto.
async fn read_head(mut stream: TcpStream) -> Option<(TcpStream, String)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 || buf.len() + n > MAX_REQUEST {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let line = String::from_utf8(buf).ok()?.lines().next()?.to_string();
    Some((stream, line))
}

/// Texto entre `?id=` e o primeiro espaço (ou `&`), só com caracteres de URL sem escape especial.
fn extract_id(request_line: &str) -> Option<String> {
    let id = request_line.split_once("?id=")?.1.split([' ', '&']).next()?;
    let valid = !id.is_empty()
        && id.len() <= MAX_ID
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.~%".contains(&b));
    valid.then(|| id.to_string())
}

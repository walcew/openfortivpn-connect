use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;

use serde::Serialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast::error::RecvError;

use crate::handlers;
use crate::protocol::{
    Frame, RequestV2, Request, Response, ResponseV2, VersionProbe, VERSION_V2,
};
use crate::session::{Event, Session};

pub const SOCKET_PATH: &str = "/var/run/openvpngui-helper.sock";

/// Decide se o uid do peer (obtido via getpeereid) pode usar o socket.
pub type Authorizer = Arc<dyn Fn(u32) -> bool + Send + Sync>;

/// Só root e o usuário do console. O dono de /dev/console é o usuário logado na
/// sessão gráfica (root no login window); é lido a cada conexão porque muda
/// com a troca rápida de usuário.
pub fn console_authorizer() -> Authorizer {
    Arc::new(|uid| {
        let console = fs::metadata("/dev/console").ok().map(|m| m.uid());
        is_authorized(uid, console)
    })
}

fn is_authorized(uid: u32, console_uid: Option<u32>) -> bool {
    uid == 0 || Some(uid) == console_uid
}

/// Cria o socket (removendo um arquivo velho) com permissão 0666: o app sem
/// privilégio precisa conectar, e quem decide o acesso é o `Authorizer`.
pub fn bind(path: &Path) -> std::io::Result<UnixListener> {
    if path.exists() {
        fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o666))?;
    Ok(listener)
}

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let listener = bind(Path::new(SOCKET_PATH))?;
    log::info!("Listening on {}", SOCKET_PATH);
    serve(listener, Arc::new(Session::new()), console_authorizer()).await;
    Ok(())
}

/// Ponto de entrada do servidor: tudo que chega pelo socket passa por aqui.
pub async fn serve(listener: UnixListener, session: Arc<Session>, authorizer: Authorizer) {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let session = session.clone();
                let authorizer = authorizer.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, session, authorizer).await {
                        log::error!("Connection error: {}", e);
                    }
                });
            }
            Err(e) => {
                log::error!("Accept error: {}", e);
            }
        }
    }
}

async fn handle_connection(
    stream: UnixStream,
    session: Arc<Session>,
    authorizer: Authorizer,
) -> Result<(), Box<dyn std::error::Error>> {
    let uid = stream.peer_cred()?.uid();
    let (reader, mut writer) = stream.into_split();

    if !authorizer(uid) {
        log::warn!("Refused connection from uid {}", uid);
        write_line(&mut writer, &Response::error("Unauthorized".to_string())).await?;
        return Ok(());
    }

    let mut lines = BufReader::new(reader).lines();

    // Read exactly one line (one JSON request per connection in v1)
    let Some(first) = lines.next_line().await? else {
        return Ok(());
    };
    let first = first.trim().to_string();
    if first.is_empty() {
        return Ok(());
    }
    log::debug!("Received: {}", first);

    let is_v2 = serde_json::from_str::<VersionProbe>(&first)
        .map(|p| p.v.is_some())
        .unwrap_or(false);

    if !is_v2 {
        let response = match serde_json::from_str::<Request>(&first) {
            Ok(request) => {
                // Run handler in blocking task since some handlers do I/O
                tokio::task::spawn_blocking(move || handlers::handle(request))
                    .await
                    .unwrap_or_else(|e| Response::error(format!("Handler panicked: {}", e)))
            }
            Err(e) => Response::error(format!("Invalid request: {}", e)),
        };
        return write_line(&mut writer, &response).await;
    }

    // v2: assina antes de responder para não perder eventos, e começa pelo estado atual.
    let mut events = session.subscribe();
    write_frame(&mut writer, "event", &Event::State(session.state())).await?;
    let mut pending = Some(first);
    loop {
        let line = match pending.take() {
            Some(l) => l,
            None => tokio::select! {
                line = lines.next_line() => match line? {
                    Some(l) => l,
                    None => return Ok(()),
                },
                event = events.recv() => {
                    match event {
                        Ok(e) => write_frame(&mut writer, "event", &e).await?,
                        Err(RecvError::Lagged(n)) => log::warn!("Client lagged, {} events dropped", n),
                        Err(RecvError::Closed) => return Ok(()),
                    }
                    continue;
                }
            },
        };
        if line.trim().is_empty() {
            continue;
        }
        let response = handle_v2_line(&session, line.trim());
        write_frame(&mut writer, "response", &response).await?;
    }
}

fn handle_v2_line(session: &Session, line: &str) -> ResponseV2 {
    let error = |msg: String| ResponseV2 { ok: false, error: Some(msg), state: None };
    match serde_json::from_str::<VersionProbe>(line) {
        Ok(VersionProbe { v: Some(VERSION_V2) }) => {}
        Ok(VersionProbe { v }) => return error(format!("Unsupported protocol version: {:?}", v)),
        Err(e) => return error(format!("Invalid request: {}", e)),
    }
    match serde_json::from_str::<RequestV2>(line) {
        Ok(request) => session.handle(request),
        Err(e) => error(format!("Invalid request: {}", e)),
    }
}

async fn write_line<T: Serialize>(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    value: &T,
) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string(value)?;
    log::debug!("Responding: {}", json);
    writer.write_all(json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

async fn write_frame<T: Serialize>(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    kind: &'static str,
    body: &T,
) -> Result<(), Box<dyn std::error::Error>> {
    write_line(writer, &Frame { v: VERSION_V2, kind, body }).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{Event, Session};
    use serde_json::{json, Value};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;
    use tokio::io::Lines;
    use tokio::net::unix::OwnedWriteHalf;

    static NEXT: AtomicU32 = AtomicU32::new(0);

    struct Client {
        lines: Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
        writer: OwnedWriteHalf,
    }

    impl Client {
        async fn send(&mut self, msg: Value) {
            let _ = self.writer.write_all(format!("{}\n", msg).as_bytes()).await;
        }

        /// Next line from the server, or None on EOF.
        async fn recv(&mut self) -> Option<Value> {
            let line = tokio::time::timeout(Duration::from_secs(2), self.lines.next_line())
                .await
                .expect("timeout waiting for the server")
                .unwrap()?;
            Some(serde_json::from_str(&line).unwrap())
        }
    }

    /// Starts the server on a temporary socket (never /var/run).
    async fn start(authorizer: Authorizer) -> (PathBuf, Arc<Session>) {
        let path = std::env::temp_dir().join(format!(
            "ovg-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let listener = bind(&path).unwrap();
        let session = Arc::new(Session::new());
        tokio::spawn(serve(listener, session.clone(), authorizer));
        (path, session)
    }

    async fn connect(path: &PathBuf) -> Client {
        let (r, writer) = tokio::net::UnixStream::connect(path).await.unwrap().into_split();
        Client { lines: BufReader::new(r).lines(), writer }
    }

    fn allow_all() -> Authorizer {
        Arc::new(|_| true)
    }

    #[tokio::test]
    async fn v1_ping_keeps_working() {
        let (path, _s) = start(allow_all()).await;
        let mut c = connect(&path).await;
        c.send(json!({"cmd": "ping"})).await;
        let r = c.recv().await.unwrap();
        assert_eq!(r["ok"], true);
        assert_eq!(r["version"], env!("CARGO_PKG_VERSION"));
        assert!(c.recv().await.is_none(), "v1 closes after one response");
    }

    #[tokio::test]
    async fn v1_invalid_request_is_an_error() {
        let (path, _s) = start(allow_all()).await;
        let mut c = connect(&path).await;
        c.send(json!({"cmd": "nope"})).await;
        let r = c.recv().await.unwrap();
        assert_eq!(r["ok"], false);
        assert!(r["error"].as_str().unwrap().starts_with("Invalid request"));
    }

    #[tokio::test]
    async fn v2_status_reports_disconnected_after_initial_state_event() {
        let (path, _s) = start(allow_all()).await;
        let mut c = connect(&path).await;
        c.send(json!({"v": 2, "cmd": "status"})).await;
        assert_eq!(
            c.recv().await.unwrap(),
            json!({"v": 2, "type": "event", "event": "state", "state": "disconnected"})
        );
        assert_eq!(
            c.recv().await.unwrap(),
            json!({"v": 2, "type": "response", "ok": true, "state": "disconnected"})
        );
    }

    #[tokio::test]
    async fn v2_connection_stays_open_and_receives_events() {
        let (path, session) = start(allow_all()).await;
        let mut c = connect(&path).await;
        c.send(json!({"v": 2, "cmd": "status"})).await;
        c.recv().await.unwrap();
        c.recv().await.unwrap();

        session.emit(Event::Log { line: "hello".into() });
        assert_eq!(
            c.recv().await.unwrap(),
            json!({"v": 2, "type": "event", "event": "log", "line": "hello"})
        );

        // Same connection still serves requests.
        c.send(json!({"v": 2, "cmd": "status"})).await;
        assert_eq!(c.recv().await.unwrap()["type"], "response");
    }

    #[tokio::test]
    async fn v2_disconnect_without_session_is_a_noop() {
        let (path, _s) = start(allow_all()).await;
        let mut c = connect(&path).await;
        c.send(json!({"v": 2, "cmd": "disconnect"})).await;
        c.recv().await.unwrap(); // initial state event
        assert_eq!(
            c.recv().await.unwrap(),
            json!({"v": 2, "type": "response", "ok": true})
        );
        let log = c.recv().await.unwrap();
        assert_eq!(log["event"], "log");
        assert!(log["line"].as_str().unwrap().contains("no active session"));
    }

    #[tokio::test]
    async fn v2_rejects_bad_requests_without_closing() {
        let (path, _s) = start(allow_all()).await;
        let mut c = connect(&path).await;
        c.send(json!({"v": 2, "cmd": "status"})).await;
        c.recv().await.unwrap();
        c.recv().await.unwrap();

        c.send(json!({"v": 2, "cmd": "nope"})).await;
        let r = c.recv().await.unwrap();
        assert_eq!(r["ok"], false);
        assert!(r["error"].as_str().unwrap().starts_with("Invalid request"));

        c.send(json!({"v": 3, "cmd": "status"})).await;
        let r = c.recv().await.unwrap();
        assert_eq!(r["ok"], false);
        assert!(r["error"].as_str().unwrap().contains("version"));

        c.send(json!({"v": 2, "cmd": "status"})).await;
        assert_eq!(c.recv().await.unwrap()["ok"], true);
    }

    #[tokio::test]
    async fn unauthorized_peer_is_refused_in_both_versions() {
        let (path, _s) = start(Arc::new(|_| false)).await;
        for msg in [json!({"cmd": "ping"}), json!({"v": 2, "cmd": "status"})] {
            let mut c = connect(&path).await;
            c.send(msg).await;
            assert_eq!(
                c.recv().await.unwrap(),
                json!({"ok": false, "error": "Unauthorized"})
            );
            assert!(c.recv().await.is_none());
        }
    }

    #[tokio::test]
    async fn authorizer_receives_the_peer_uid() {
        use std::os::unix::fs::MetadataExt;
        let seen = Arc::new(std::sync::Mutex::new(None));
        let s = seen.clone();
        let (path, _s) = start(Arc::new(move |uid| {
            *s.lock().unwrap() = Some(uid);
            true
        }))
        .await;
        let mut c = connect(&path).await;
        c.send(json!({"cmd": "ping"})).await;
        c.recv().await.unwrap();
        // The socket file is owned by this process, which is also the peer.
        let my_uid = std::fs::metadata(&path).unwrap().uid();
        assert_eq!(*seen.lock().unwrap(), Some(my_uid));
    }

    #[test]
    fn policy_accepts_only_root_and_the_console_user() {
        assert!(is_authorized(0, Some(501)));
        assert!(is_authorized(0, None));
        assert!(is_authorized(501, Some(501)));
        assert!(!is_authorized(502, Some(501)));
        assert!(!is_authorized(501, None));
    }
}

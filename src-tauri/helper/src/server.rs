use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;

use serde::Serialize;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast::error::RecvError;

use crate::net::{self, SystemOs};
use crate::protocol::{Frame, FrameKind, RequestV2, ResponseV2, VERSION_V2};
use crate::session::{Event, Session};

pub const SOCKET_PATH: &str = "/var/run/vpnconnect-helper.sock";

/// Decide se o uid do peer (obtido via getpeereid) pode usar o socket.
pub type Authorizer = Arc<dyn Fn(u32) -> bool + Send + Sync>;

/// Só root e o usuário do console. O dono de /dev/console é o usuário logado na
/// sessão gráfica (root no login window); é lido a cada checagem porque muda
/// com a troca rápida de usuário.
pub fn console_authorizer() -> Authorizer {
    policy_authorizer(|| fs::metadata("/dev/console").ok().map(|m| m.uid()))
}

/// A regra de `is_authorized` com a origem do uid do console injetável.
pub fn policy_authorizer(console_uid: impl Fn() -> Option<u32> + Send + Sync + 'static) -> Authorizer {
    Arc::new(move |uid| is_authorized(uid, console_uid()))
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
    let session = Arc::new(Session::new(Arc::new(SystemOs::default())));
    let watched = session.clone();
    tokio::spawn(async move { net::watch::run(|| watched.network_changed()).await });
    serve(listener, session, console_authorizer()).await;
    Ok(())
}

/// Cada conexão roda numa task própria, para um cliente lento não travar o accept.
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

type Writer = tokio::net::unix::OwnedWriteHalf;

async fn refuse(writer: &mut Writer, uid: u32) -> Result<(), Box<dyn std::error::Error>> {
    log::warn!("Refused uid {}", uid);
    write_line(writer, &ResponseV2::error("Unauthorized".to_string())).await
}

async fn handle_connection(
    stream: UnixStream,
    session: Arc<Session>,
    authorizer: Authorizer,
) -> Result<(), Box<dyn std::error::Error>> {
    let uid = stream.peer_cred()?.uid();
    let (reader, mut writer) = stream.into_split();

    if !authorizer(uid) {
        return refuse(&mut writer, uid).await;
    }

    let mut lines = BufReader::new(reader).lines();

    // A primeira linha já é uma requisição. Ela pode trazer a senha, por isso nunca vai ao log.
    let Some(first) = lines.next_line().await? else {
        return Ok(());
    };
    if first.trim().is_empty() {
        return Ok(());
    }
    let parsed = serde_json::from_str::<Value>(first.trim());

    // Assina antes de responder para não perder eventos, e começa pelo estado atual.
    // A conexão é longa, então a autorização é reavaliada a cada requisição e a cada
    // evento: o usuário do console pode mudar (troca rápida de usuário) depois do accept.
    let mut events = session.subscribe();
    write_frame(&mut writer, FrameKind::Event, &Event::State(session.state())).await?;
    let mut pending = Some(parsed);
    loop {
        let parsed = match pending.take() {
            Some(p) => p,
            None => tokio::select! {
                line = lines.next_line() => match line? {
                    Some(l) if l.trim().is_empty() => continue,
                    Some(l) => serde_json::from_str::<Value>(&l),
                    None => return Ok(()),
                },
                event = events.recv() => {
                    match event {
                        Ok(e) => {
                            if !authorizer(uid) {
                                return refuse(&mut writer, uid).await;
                            }
                            write_frame(&mut writer, FrameKind::Event, &e).await?
                        }
                        Err(RecvError::Lagged(n)) => log::warn!("Client lagged, {} events dropped", n),
                        Err(RecvError::Closed) => return Ok(()),
                    }
                    continue;
                }
            },
        };
        if !authorizer(uid) {
            return refuse(&mut writer, uid).await;
        }
        let response = handle_v2(&session, parsed);
        write_frame(&mut writer, FrameKind::Response, &response).await?;
    }
}

fn handle_v2(session: &Arc<Session>, parsed: serde_json::Result<Value>) -> ResponseV2 {
    let request = parsed
        .map_err(|e| format!("Invalid request: {}", e))
        .and_then(RequestV2::from_value);
    match request {
        Ok(RequestV2::Status) => ResponseV2::ok(Some(session.state())),
        Ok(RequestV2::Version) => ResponseV2::version(env!("CARGO_PKG_VERSION")),
        Ok(RequestV2::Disconnect) => {
            session.disconnect();
            ResponseV2::ok(None)
        }
        Ok(RequestV2::Cancel) => {
            session.cancel();
            ResponseV2::ok(None)
        }
        Ok(RequestV2::Connect { profile, password, otp }) => match session.connect(profile, password, otp) {
            Ok(()) => ResponseV2::ok(None),
            Err(e) => ResponseV2::error(e),
        },
        Err(msg) => ResponseV2::error(msg),
    }
}

async fn write_line<T: Serialize>(
    writer: &mut Writer,
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
    writer: &mut Writer,
    kind: FrameKind,
    body: &T,
) -> Result<(), Box<dyn std::error::Error>> {
    write_line(writer, &Frame { v: VERSION_V2, kind, body }).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::Event;
    use crate::testing::{allow_all, connect, start};
    use serde_json::json;
    use std::sync::atomic::Ordering;

    #[tokio::test]
    async fn version_reports_the_helper_version() {
        let (path, _s) = start(allow_all()).await;
        let mut c = connect(&path).await;
        c.send(json!({"v": 2, "cmd": "version"})).await;
        c.recv().await.unwrap(); // evento inicial de estado
        assert_eq!(
            c.recv().await.unwrap(),
            json!({"v": 2, "type": "response", "ok": true, "version": env!("CARGO_PKG_VERSION")})
        );
    }

    #[tokio::test]
    async fn request_without_protocol_version_is_an_error() {
        let (path, _s) = start(allow_all()).await;
        let mut c = connect(&path).await;
        c.send(json!({"cmd": "status"})).await;
        c.recv().await.unwrap(); // evento inicial de estado
        let r = c.recv().await.unwrap();
        assert_eq!(r["ok"], false);
        assert!(r["error"].as_str().unwrap().contains("version"));
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

        // A mesma conexão continua atendendo requisições.
        c.send(json!({"v": 2, "cmd": "status"})).await;
        assert_eq!(c.recv().await.unwrap()["type"], "response");
    }

    #[tokio::test]
    async fn v2_disconnect_without_session_is_a_noop() {
        let (path, _s) = start(allow_all()).await;
        let mut c = connect(&path).await;
        c.send(json!({"v": 2, "cmd": "disconnect"})).await;
        c.recv().await.unwrap(); // evento inicial de estado
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
    async fn unauthorized_peer_is_refused() {
        let (path, _s) = start(Arc::new(|_| false)).await;
        let mut c = connect(&path).await;
        c.send(json!({"v": 2, "cmd": "status"})).await;
        assert_eq!(
            c.recv().await.unwrap(),
            json!({"ok": false, "error": "Unauthorized"})
        );
        assert!(c.recv().await.is_none());
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
        c.send(json!({"v": 2, "cmd": "status"})).await;
        c.recv().await.unwrap();
        // O arquivo do socket é deste processo, que também é o peer.
        let my_uid = std::fs::metadata(&path).unwrap().uid();
        assert_eq!(*seen.lock().unwrap(), Some(my_uid));
    }

    #[tokio::test]
    async fn v2_request_is_refused_when_authorization_is_revoked_mid_connection() {
        use std::sync::atomic::AtomicBool;
        let allowed = Arc::new(AtomicBool::new(true));
        let a = allowed.clone();
        let (path, _s) = start(Arc::new(move |_| a.load(Ordering::SeqCst))).await;
        let mut c = connect(&path).await;
        c.send(json!({"v": 2, "cmd": "status"})).await;
        c.recv().await.unwrap();
        assert_eq!(c.recv().await.unwrap()["ok"], true);

        // Troca rápida de usuário: o peer deixa de ser o usuário do console.
        allowed.store(false, Ordering::SeqCst);
        c.send(json!({"v": 2, "cmd": "disconnect"})).await;
        assert_eq!(
            c.recv().await.unwrap(),
            json!({"ok": false, "error": "Unauthorized"})
        );
        assert!(c.recv().await.is_none());
    }

    #[tokio::test]
    async fn v2_events_stop_when_authorization_is_revoked_mid_connection() {
        use std::sync::atomic::AtomicBool;
        let allowed = Arc::new(AtomicBool::new(true));
        let a = allowed.clone();
        let (path, session) = start(Arc::new(move |_| a.load(Ordering::SeqCst))).await;
        let mut c = connect(&path).await;
        c.send(json!({"v": 2, "cmd": "status"})).await;
        c.recv().await.unwrap();
        c.recv().await.unwrap();

        allowed.store(false, Ordering::SeqCst);
        session.emit(Event::Log { line: "secret".into() });
        assert_eq!(
            c.recv().await.unwrap(),
            json!({"ok": false, "error": "Unauthorized"})
        );
        assert!(c.recv().await.is_none());
    }

    #[tokio::test]
    async fn real_policy_through_the_socket_follows_the_console_user() {
        use std::os::unix::fs::MetadataExt;
        let probe = std::env::temp_dir().join(format!("ovg-uid-{}", std::process::id()));
        std::fs::write(&probe, "").unwrap();
        let my_uid = std::fs::metadata(&probe).unwrap().uid();
        std::fs::remove_file(&probe).unwrap();
        if my_uid == 0 {
            return; // root é sempre aceito, então a regra não é exercitada
        }
        for (console, accepted) in [(my_uid + 1, false), (my_uid, true)] {
            let (path, _s) = start(policy_authorizer(move || Some(console))).await;
            let mut c = connect(&path).await;
            c.send(json!({"v": 2, "cmd": "status"})).await;
            // Aceito: o primeiro quadro é o evento de estado, sem `ok`.
            assert_eq!(c.recv().await.unwrap()["ok"] != false, accepted);
        }
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

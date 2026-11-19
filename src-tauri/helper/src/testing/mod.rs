//! Apoio aos testes no seam da sessão: cliente do socket, fake da camada de SO e
//! gateway Fortinet falso.

pub mod fake_gateway;
pub mod fake_os;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

use tokio_rustls::rustls::RootCertStore;

use crate::fortinet::CertTrust;
use crate::server::{bind, serve, Authorizer};
use crate::session::Session;
use fake_os::FakeOs;

static NEXT: AtomicU32 = AtomicU32::new(0);

/// Serializa os testes que escutam ou testam o `sso_port` do `FakeGateway`: com um de cada
/// vez, nenhum outro teste prende a porta que um deles espera achar livre ou fechada.
pub static SAML_PORTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub struct Client {
    lines: Lines<BufReader<OwnedReadHalf>>,
    writer: OwnedWriteHalf,
}

impl Client {
    pub async fn send(&mut self, msg: Value) {
        let _ = self.writer.write_all(format!("{}\n", msg).as_bytes()).await;
    }

    /// Próxima linha do servidor, ou None no EOF.
    pub async fn recv(&mut self) -> Option<Value> {
        let line = tokio::time::timeout(Duration::from_secs(5), self.lines.next_line())
            .await
            .expect("timeout waiting for the server")
            .unwrap()?;
        Some(serde_json::from_str(&line).unwrap())
    }

    /// Próximo quadro que não é evento de log nem de banda, que chegam a qualquer momento.
    pub async fn recv_skipping_logs(&mut self) -> Value {
        loop {
            let v = self.recv().await.expect("server closed the connection");
            if v["event"] != "log" && v["event"] != "bandwidth" {
                return v;
            }
        }
    }
}

/// Sobe o servidor num socket temporário (nunca em /var/run) com o fake de SO.
pub async fn start(authorizer: Authorizer) -> (PathBuf, Arc<Session>) {
    start_server(authorizer, Arc::new(FakeOs::default())).await
}

/// Servidor sem checagem de uid com o fake de SO dado, que volta para inspeção.
pub async fn start_with_os(os: FakeOs) -> (PathBuf, Arc<Session>, Arc<FakeOs>) {
    let os = Arc::new(os);
    let (path, session) = start_server(allow_all(), os.clone()).await;
    (path, session, os)
}

/// Servidor com o fake de SO padrão e a validação de certificado usando estas raízes em vez das do sistema.
pub async fn start_with_roots(roots: RootCertStore) -> (PathBuf, Arc<Session>) {
    start_session(allow_all(), Session::with_trust(Arc::new(FakeOs::default()), CertTrust::with_roots(roots))).await
}

/// Como `start_with_os`, com um prazo curto para o push.
pub async fn start_with_push_timeout(timeout: Duration) -> (PathBuf, Arc<Session>, Arc<FakeOs>) {
    let os = Arc::new(FakeOs::default());
    let (path, session) = start_session(allow_all(), Session::new(os.clone()).with_push_timeout(timeout)).await;
    (path, session, os)
}

/// Como `start_with_os`, com a banda emitida neste intervalo em vez de a cada segundo.
pub async fn start_with_bandwidth_interval(interval: Duration) -> (PathBuf, Arc<Session>, Arc<FakeOs>) {
    let os = Arc::new(FakeOs::default());
    let (path, session) = start_session(allow_all(), Session::new(os.clone()).with_bandwidth_interval(interval)).await;
    (path, session, os)
}

/// Como `start_with_os`, com o LCP echo neste intervalo em vez de a cada 10 s.
pub async fn start_with_echo_interval(interval: Duration) -> (PathBuf, Arc<Session>, Arc<FakeOs>) {
    let os = Arc::new(FakeOs::default());
    let (path, session) = start_session(allow_all(), Session::new(os.clone()).with_echo_interval(interval)).await;
    (path, session, os)
}

async fn start_server(authorizer: Authorizer, os: Arc<FakeOs>) -> (PathBuf, Arc<Session>) {
    start_session(authorizer, Session::new(os)).await
}

pub async fn start_session(authorizer: Authorizer, session: Session) -> (PathBuf, Arc<Session>) {
    let path = std::env::temp_dir().join(format!(
        "ovg-{}-{}.sock",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let listener = bind(&path).unwrap();
    let session = Arc::new(session);
    tokio::spawn(serve(listener, session.clone(), authorizer));
    (path, session)
}

pub async fn connect(path: &PathBuf) -> Client {
    let (r, writer) = tokio::net::UnixStream::connect(path).await.unwrap().into_split();
    Client { lines: BufReader::new(r).lines(), writer }
}

pub fn allow_all() -> Authorizer {
    Arc::new(|_| true)
}

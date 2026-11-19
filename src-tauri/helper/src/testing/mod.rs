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

use crate::server::{bind, serve, Authorizer};
use crate::session::Session;
use fake_os::FakeOs;

static NEXT: AtomicU32 = AtomicU32::new(0);

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

    /// Próximo quadro que não é evento de log.
    pub async fn recv_skipping_logs(&mut self) -> Value {
        loop {
            let v = self.recv().await.expect("server closed the connection");
            if v["event"] != "log" {
                return v;
            }
        }
    }
}

/// Sobe o servidor num socket temporário (nunca em /var/run) com o fake de SO.
pub async fn start(authorizer: Authorizer) -> (PathBuf, Arc<Session>) {
    let (path, session, _os) = start_with_os(authorizer).await;
    (path, session)
}

pub async fn start_with_os(authorizer: Authorizer) -> (PathBuf, Arc<Session>, Arc<FakeOs>) {
    let path = std::env::temp_dir().join(format!(
        "ovg-{}-{}.sock",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let listener = bind(&path).unwrap();
    let os = Arc::new(FakeOs::default());
    let session = Arc::new(Session::new(os.clone()));
    tokio::spawn(serve(listener, session.clone(), authorizer));
    (path, session, os)
}

pub async fn connect(path: &PathBuf) -> Client {
    let (r, writer) = tokio::net::UnixStream::connect(path).await.unwrap().into_split();
    Client { lines: BufReader::new(r).lines(), writer }
}

pub fn allow_all() -> Authorizer {
    Arc::new(|_| true)
}

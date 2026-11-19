use std::sync::Mutex;

use serde::Serialize;
use tokio::sync::broadcast;

use crate::protocol::{RequestV2, ResponseV2};

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum State {
    Disconnected,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "kebab-case")]
pub enum Event {
    State(State),
    Log { line: String },
}

/// Dono do estado da VPN e da fonte de eventos do protocolo v2. Hoje só existe o
/// estado desconectado; o Engine passa a mexer aqui nos próximos tickets.
pub struct Session {
    state: Mutex<State>,
    events: broadcast::Sender<Event>,
}

impl Session {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State::Disconnected),
            events: broadcast::channel(256).0,
        }
    }

    pub fn state(&self) -> State {
        self.state.lock().unwrap().clone()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    pub fn emit(&self, event: Event) {
        // Sem assinantes o envio falha, o que é esperado.
        let _ = self.events.send(event);
    }

    pub fn handle(&self, request: RequestV2) -> ResponseV2 {
        match request {
            RequestV2::Status => ResponseV2 { ok: true, error: None, state: Some(self.state()) },
            RequestV2::Disconnect => {
                // Sem Engine ainda não há sessão a encerrar.
                self.emit(Event::Log { line: "disconnect: no active session".into() });
                ResponseV2 { ok: true, error: None, state: None }
            }
        }
    }
}

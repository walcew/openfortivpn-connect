//! Helper falso roteirizado para os testes de ponta a ponta da CLI.
//!
//! Escuta no socket do diretório de teste e fala o protocolo v2 como o Helper real: cada
//! conexão recebe primeiro o evento `state` com o estado atual e depois, a cada request, os
//! quadros que o roteiro do teste devolver (a `response` e os eventos que vierem depois).
//! Os requests recebidos ficam registrados para o teste conferir.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

type Script = dyn Fn(&Value) -> Vec<Value> + Send + Sync;

pub struct FakeHelper {
    requests: Arc<Mutex<Vec<Value>>>,
}

impl FakeHelper {
    /// Sobe o Helper em `socket` com o estado `state` (o corpo do evento, ex.
    /// `{"state": "disconnected"}`). `script` responde a cada request com a lista de quadros.
    pub fn start(socket: &Path, state: Value, script: impl Fn(&Value) -> Vec<Value> + Send + Sync + 'static) -> Self {
        let listener = UnixListener::bind(socket).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let script: Arc<Script> = Arc::new(script);
        let log = requests.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let (state, script, log) = (state.clone(), script.clone(), log.clone());
                std::thread::spawn(move || {
                    let reader = BufReader::new(stream.try_clone().unwrap());
                    let mut greeted = false;
                    for line in reader.lines().map_while(Result::ok) {
                        let request: Value = serde_json::from_str(&line).unwrap();
                        // Como o Helper real: o estado atual sai antes da primeira resposta.
                        if !greeted {
                            greeted = true;
                            let _ = writeln!(stream, "{}", event(state_event(&state)));
                        }
                        log.lock().unwrap().push(request.clone());
                        for frame in script(&request) {
                            let _ = writeln!(stream, "{}", frame);
                        }
                    }
                });
            }
        });
        Self { requests }
    }

    /// Helper que responde `status` com `state`, `version` com a versão e o resto com ok.
    pub fn with_state(socket: &Path, state: Value) -> Self {
        let status = state.clone();
        Self::start(socket, state, move |req| match req["cmd"].as_str() {
            Some("status") => vec![response(status.clone())],
            Some("version") => vec![response(json!({"version": "0.4.0"}))],
            _ => vec![response(json!({}))],
        })
    }

    pub fn requests(&self) -> Vec<Value> {
        self.requests.lock().unwrap().clone()
    }
}

fn state_event(state: &Value) -> Value {
    let mut body = json!({"event": "state"});
    body.as_object_mut().unwrap().extend(state.as_object().unwrap().clone());
    body
}

/// `response` com `ok: true` e os campos de `body`.
pub fn response(body: Value) -> Value {
    let mut frame = json!({"v": 2, "type": "response", "ok": true});
    frame.as_object_mut().unwrap().extend(body.as_object().unwrap().clone());
    frame
}

/// `event` com os campos de `body` (que leva o `event`).
pub fn event(body: Value) -> Value {
    let mut frame = json!({"v": 2, "type": "event"});
    frame.as_object_mut().unwrap().extend(body.as_object().unwrap().clone());
    frame
}

/// A recusa do Helper a um uid que não é root nem o usuário do console: sai sem envelope.
pub fn unauthorized() -> Value {
    json!({"ok": false, "error": "Unauthorized"})
}

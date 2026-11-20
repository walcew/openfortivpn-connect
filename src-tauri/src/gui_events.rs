//! Camada Tauri sobre o cliente do Helper: liga o canal de eventos ao manager, aos eventos
//! do front, às notificações e à tray.

use std::sync::Mutex;
use std::time::Instant;

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager};

use crate::helper_client::{run_events, socket_path, Cause, Incoming, Totals};
use crate::models::*;
use crate::vpn_manager::VpnManager;

/// Os eventos são a única fonte da verdade do estado. O lock é
/// bloqueante (e não `try_lock`) para que um evento chegando durante um
/// connect/disconnect em andamento espere o comando soltar o manager em vez de se perder.
fn apply_state(manager: &Mutex<VpnManager>, state: &ConnectionState) {
    manager
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .sync_state_from_payload(&ConnectionStatusPayload::from(state));
}

/// Evento do Tauri que uma transição de estado pede além do próprio estado: `saml-url` na
/// transição `connecting` -> `waiting-saml` e `cert-warning` na `connecting` -> erro por
/// certificado não confiável. `connecting` guarda o Profile da tentativa em curso, então o
/// estado inicial repetido de uma reconexão do canal não reabre a aba nem o diálogo.
fn transition(connecting: &mut Option<String>, state: &ConnectionState, cert_digest: Option<&str>) -> Option<(&'static str, Value)> {
    if let ConnectionState::Connecting { profile_id } = state {
        *connecting = Some(profile_id.clone());
        return None;
    }
    let profile_id = connecting.take()?;
    match (state, cert_digest) {
        // O front abre a URL no navegador padrão e mostra o diálogo "Trust & Reconnect".
        (ConnectionState::WaitingSaml { url, .. }, _) => Some(("saml-url", json!({"url": url}))),
        (ConnectionState::Error { .. }, Some(digest)) => Some(("cert-warning", json!({"digest": digest, "profile_id": profile_id}))),
        _ => None,
    }
}

const RECONNECT_HINT: &str = "Use Connect in the app or the menu bar to reconnect.";
const EXPIRING_HINT: &str = "Reconnect afterwards to keep using the VPN.";

/// Guarda em `connected` se `state` é `connected` e devolve o valor anterior.
fn swap_connected(connected: &mut bool, state: &ConnectionState) -> bool {
    std::mem::replace(connected, matches!(state, ConnectionState::Connected { .. }))
}

/// Notificação (título, corpo) de uma sessão que caiu ou expirou. Só na transição a partir de
/// `connected`: o `disconnected` repetido ao reabrir o canal de eventos não notifica de novo.
fn drop_notice(was_connected: bool, cause: Option<Cause>) -> Option<(&'static str, &'static str)> {
    match cause.filter(|_| was_connected)? {
        Cause::TunnelDropped => Some(("Disconnected: tunnel dropped", RECONNECT_HINT)),
        Cause::Expired => Some(("Session expired", RECONNECT_HINT)),
    }
}

/// Título do aviso de expiração, no horário local.
fn expiring_notice(expires_at: &str) -> Option<String> {
    let at = DateTime::parse_from_rfc3339(expires_at).ok()?.with_timezone(&chrono::Local);
    Some(format!("Session expires at {}", at.format("%H:%M")))
}

fn notify(app: &AppHandle, title: &str, body: &str) {
    use tauri_plugin_notification::NotificationExt;
    if let Err(e) = app.notification().builder().title(title).body(body).show() {
        log::warn!("Failed to show notification: {}", e);
    }
}

/// Última amostra de banda: os totais e o instante em que chegaram.
struct Sample {
    totals: Totals,
    at: Instant,
}

/// Converte os totais do Helper no payload que o frontend já consome; a velocidade
/// (bytes/s) vem da diferença para a amostra anterior, e a primeira amostra tem velocidade 0.
/// Qualquer estado zera a amostra: os contadores recomeçam a cada sessão, e o Helper manda
/// o estado ao abrir (ou reabrir) o canal, antes de qualquer banda.
fn bandwidth_update(prev: &mut Option<Sample>, incoming: &Incoming, now: Instant) -> Option<BandwidthPayload> {
    let totals = match incoming {
        Incoming::State { .. } => {
            *prev = None;
            return None;
        }
        Incoming::Bandwidth(totals) => *totals,
        Incoming::Log(_) | Incoming::Expiring(_) => return None,
    };
    let speed = |total: u64, before: u64, secs: f64| if secs > 0.0 { total.saturating_sub(before) as f64 / secs } else { 0.0 };
    let (rx_speed, tx_speed) = match prev {
        Some(Sample { totals: before, at }) => {
            let secs = now.duration_since(*at).as_secs_f64();
            (speed(totals.rx_bytes, before.rx_bytes, secs), speed(totals.tx_bytes, before.tx_bytes, secs))
        }
        None => (0.0, 0.0),
    };
    *prev = Some(Sample { totals, at: now });
    Some(BandwidthPayload {
        rx_bytes: totals.rx_bytes,
        tx_bytes: totals.tx_bytes,
        rx_speed,
        tx_speed,
        timestamp: Utc::now().to_rfc3339(),
    })
}

/// Liga o canal de eventos ao manager, aos eventos do Tauri e à tray.
pub fn start(app: AppHandle) {
    std::thread::spawn(move || {
        let mut connecting = None;
        let mut connected = false;
        let mut sample = None;
        run_events(&socket_path(), |incoming| {
            if let Some(payload) = bandwidth_update(&mut sample, &incoming, Instant::now()) {
                let _ = app.emit("bandwidth-update", payload);
            }
            match incoming {
                Incoming::State { state, cert_digest, cause } => {
                    if let Some((event, payload)) = transition(&mut connecting, &state, cert_digest.as_deref()) {
                        let _ = app.emit(event, payload);
                    }
                    // Desktop não tem botão de ação na notificação: reconectar é o Connect da janela e da tray.
                    let was_connected = swap_connected(&mut connected, &state);
                    if let Some((title, body)) = drop_notice(was_connected, cause) {
                        notify(&app, title, body);
                    }
                    crate::tray::update_tray_icon(&app, &state);
                    let _ = app.emit("connection-status-changed", ConnectionStatusPayload::from(&state));
                    apply_state(&app.state::<Mutex<VpnManager>>(), &state);
                    // Depois do sync, para o menu refletir o estado novo.
                    crate::tray::refresh_tray_menu(&app);
                }
                Incoming::Bandwidth(_) => {}
                Incoming::Expiring(expires_at) => {
                    if let Some(title) = expiring_notice(&expires_at) {
                        notify(&app, &title, EXPIRING_HINT);
                    }
                }
                Incoming::Log(message) => {
                    let _ = app.emit(
                        "log-line",
                        // shortcut: o Helper não manda nível, tudo vai como info; evolui se o evento de log ganhar nível
                        LogLinePayload { timestamp: Utc::now().to_rfc3339(), level: "info".into(), message },
                    );
                }
            }
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper_client::parse_frame;
    use std::time::Duration;

    fn event(body: Value) -> Value {
        let mut frame = json!({"v": 2, "type": "event"});
        frame.as_object_mut().unwrap().extend(body.as_object().unwrap().clone());
        frame
    }

    fn error(message: &str) -> ConnectionState {
        ConnectionState::Error { message: message.into() }
    }

    fn connecting(id: &str) -> ConnectionState {
        ConnectionState::Connecting { profile_id: id.into() }
    }

    #[test]
    fn certificate_warning_comes_from_the_cert_digest_field() {
        let digest = "ab".repeat(32);
        let mut pending = None;
        assert!(transition(&mut pending, &connecting("p1"), None).is_none());
        let action = transition(&mut pending, &error("TLS handshake failed"), Some(&digest));
        assert_eq!(action, Some(("cert-warning", json!({"digest": digest, "profile_id": "p1"}))));
    }

    #[test]
    fn digest_text_in_the_reason_does_not_open_the_dialog() {
        let reason = format!("Login failed: sha256 digest {}", "cd".repeat(32));
        let mut pending = None;
        transition(&mut pending, &connecting("p1"), None);
        assert!(transition(&mut pending, &error(&reason), None).is_none());
    }

    #[test]
    fn repeated_old_error_after_a_channel_reconnect_does_not_reopen_the_dialog() {
        let digest = "ab".repeat(32);
        let mut pending = None;
        transition(&mut pending, &connecting("p1"), None);
        assert!(transition(&mut pending, &error("x"), Some(&digest)).is_some());
        // O estado inicial da conexão reaberta repete o erro, sem um connecting antes.
        assert!(transition(&mut pending, &error("x"), Some(&digest)).is_none());
    }

    fn bandwidth_frame(rx: u64, tx: u64) -> Incoming {
        let frame = json!({"v": 2, "type": "event", "event": "bandwidth", "rx_bytes": rx, "tx_bytes": tx});
        parse_frame(&frame).expect("not a bandwidth event")
    }

    fn state_frame(state: &str) -> Incoming {
        parse_frame(&event(json!({"event": "state", "state": state}))).unwrap()
    }

    #[test]
    fn bandwidth_event_becomes_a_payload_with_the_speed_from_the_previous_sample() {
        let (mut prev, t0) = (None, Instant::now());

        let first = bandwidth_update(&mut prev, &bandwidth_frame(1000, 500), t0).unwrap();
        assert_eq!((first.rx_bytes, first.tx_bytes, first.rx_speed, first.tx_speed), (1000, 500, 0.0, 0.0));

        let second = bandwidth_update(&mut prev, &bandwidth_frame(3000, 500), t0 + Duration::from_secs(2)).unwrap();
        assert_eq!((second.rx_bytes, second.tx_bytes), (3000, 500));
        assert_eq!((second.rx_speed, second.tx_speed), (1000.0, 0.0));
        assert!(DateTime::parse_from_rfc3339(&second.timestamp).is_ok());
    }

    #[test]
    fn a_state_event_resets_the_speed_baseline() {
        // `connecting` de uma sessão nova e o estado enviado ao reabrir o canal seguem o mesmo caminho.
        for state in ["connecting", "connected", "disconnected"] {
            let (mut prev, t0) = (None, Instant::now());
            bandwidth_update(&mut prev, &bandwidth_frame(9_000_000, 9_000_000), t0);

            assert!(bandwidth_update(&mut prev, &state_frame(state), t0 + Duration::from_secs(1)).is_none());
            let first = bandwidth_update(&mut prev, &bandwidth_frame(100, 100), t0 + Duration::from_secs(2)).unwrap();
            assert_eq!((first.rx_speed, first.tx_speed), (0.0, 0.0), "after {}", state);
        }
    }

    #[test]
    fn state_event_during_a_running_command_is_not_lost() {
        let manager = Mutex::new(VpnManager::new().unwrap());
        let held = manager.lock().unwrap(); // connect/disconnect em andamento
        std::thread::scope(|s| {
            let event = s.spawn(|| {
                apply_state(&manager, &ConnectionState::Connecting { profile_id: "p1".into() })
            });
            std::thread::sleep(Duration::from_millis(200));
            assert!(!event.is_finished(), "event must wait for the lock, not give up");
            drop(held);
        });
        assert!(matches!(
            manager.lock().unwrap().get_state(),
            ConnectionState::Connecting { profile_id } if profile_id == "p1"
        ));
    }

    #[test]
    fn saml_url_opens_only_on_the_transition_from_connecting() {
        let waiting = ConnectionState::WaitingSaml { profile_id: "p1".into(), url: "https://vpn/x".into() };
        let mut pending = None;
        // Estado inicial de uma reconexão do canal, sem connecting antes: não reabre.
        assert!(transition(&mut pending, &waiting, None).is_none());
        transition(&mut pending, &connecting("p1"), None);
        assert_eq!(transition(&mut pending, &waiting, None), Some(("saml-url", json!({"url": "https://vpn/x"}))));
        assert!(transition(&mut pending, &waiting, None).is_none());
    }

    fn connected_state() -> ConnectionState {
        ConnectionState::Connected { profile_id: "p1".into(), ip: "10.0.0.2".into(), since: Utc::now(), dns_servers: vec![], dns_domains: vec![] }
    }

    #[test]
    fn dropped_or_expired_session_notifies_only_on_the_transition_from_connected() {
        // Os estados que o canal entrega em ordem, com o flag carregado entre eles.
        let notices = |states: &[(ConnectionState, Option<Cause>)]| {
            let mut connected = false;
            states.iter().map(|(s, c)| drop_notice(swap_connected(&mut connected, s), *c).map(|n| n.0)).collect::<Vec<_>>()
        };
        for (cause, title) in [(Cause::TunnelDropped, "Disconnected: tunnel dropped"), (Cause::Expired, "Session expired")] {
            // O estado inicial de um canal reaberto repete o disconnected com a causa.
            let seen = notices(&[(connected_state(), None), (error("x"), Some(cause)), (error("x"), Some(cause))]);
            assert_eq!(seen, [None, Some(title), None]);
        }
    }

    #[test]
    fn login_error_and_normal_disconnect_do_not_notify() {
        assert!(drop_notice(true, None).is_none());
        assert!(drop_notice(false, None).is_none());
        // Causa sem ter passado por connected (ex.: canal aberto depois da queda já notificada).
        assert!(drop_notice(false, Some(Cause::Expired)).is_none());
    }

    #[test]
    fn expiring_notice_shows_the_local_time() {
        let at = chrono::Local::now() + chrono::Duration::minutes(15);
        let title = expiring_notice(&at.to_rfc3339()).unwrap();
        assert_eq!(title, format!("Session expires at {}", at.format("%H:%M")));
        assert!(expiring_notice("not a time").is_none());
    }
}

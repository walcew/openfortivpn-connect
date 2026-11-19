//! Fake da camada de SO: registra cada chamada e guarda o canal de pacotes.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Mutex;

use crate::net::{Os, Packets, Route};

/// Next-hop que o fake diz ter usado no /32: o do default no connect e o do default novo na troca de rede.
pub const FIRST_VIA: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
pub const NEW_VIA: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));

#[derive(Debug, Clone, PartialEq)]
pub enum OsCall {
    Up { ip: Ipv4Addr, peer: Ipv4Addr, mtu: u16 },
    AddRoute(Route),
    AddGatewayRoute(IpAddr),
    MoveGatewayRoute(IpAddr),
    SetDns { servers: Vec<Ipv4Addr>, suffixes: Vec<String> },
    RemoveDns,
    RemoveGatewayRoute(IpAddr, IpAddr),
    Down,
}

/// Como o `add_route` do fake se comporta.
#[derive(Default, Clone, Copy, PartialEq)]
pub enum Failure {
    #[default]
    None,
    Error,
    Panic,
}

pub struct FakeOs {
    calls: Mutex<Vec<OsCall>>,
    packets: Mutex<Option<Packets>>,
    add_route: Failure,
    add_gateway_route: Failure,
    set_dns: Failure,
    /// O próximo `move_gateway_route` falha (default ainda ausente na troca de Wi-Fi).
    fail_next_move: AtomicBool,
    state_file: PathBuf,
}

static STATE_FILE_SEQ: AtomicU32 = AtomicU32::new(0);

impl Default for FakeOs {
    /// Arquivo de estado próprio no diretório temporário, para os testes não se cruzarem.
    fn default() -> Self {
        let name = format!("ovg-state-{}-{}.json", std::process::id(), STATE_FILE_SEQ.fetch_add(1, Ordering::Relaxed));
        Self {
            calls: Mutex::default(),
            packets: Mutex::default(),
            add_route: Failure::None,
            add_gateway_route: Failure::None,
            set_dns: Failure::None,
            fail_next_move: AtomicBool::new(false),
            state_file: std::env::temp_dir().join(name),
        }
    }
}

impl FakeOs {
    /// Fake com o arquivo de estado neste caminho (ex.: com resíduo de um crash).
    pub fn with_state_file(state_file: PathBuf) -> Self {
        let mut os = Self::default();
        os.state_file = state_file;
        os
    }

    /// Faz o próximo `move_gateway_route` falhar.
    pub fn fail_next_move(&self) {
        self.fail_next_move.store(true, Ordering::SeqCst);
    }

    /// Conteúdo do arquivo de estado, ou None se não existe.
    pub fn saved_state(&self) -> Option<serde_json::Value> {
        std::fs::read(&self.state_file).ok().map(|d| serde_json::from_slice(&d).unwrap())
    }

    /// Fake cujo `add_route` falha (erro ou pânico) depois de registrar a chamada.
    pub fn failing_add_route(failure: Failure) -> Self {
        let mut os = Self::default();
        os.add_route = failure;
        os
    }

    /// Fake cujo `add_gateway_route` falha com erro depois de registrar a chamada.
    pub fn failing_add_gateway_route() -> Self {
        let mut os = Self::default();
        os.add_gateway_route = Failure::Error;
        os
    }

    /// Fake cujo `set_dns` falha com erro depois de registrar a chamada.
    pub fn failing_set_dns() -> Self {
        let mut os = Self::default();
        os.set_dns = Failure::Error;
        os
    }

    pub fn calls(&self) -> Vec<OsCall> {
        self.calls.lock().unwrap().clone()
    }

    /// O lado "interface" do canal de pacotes entregue no `up`.
    pub fn take_packets(&self) -> Packets {
        self.packets.lock().unwrap().take().expect("interface is not up")
    }

    /// O que continua aplicado depois de repassar as chamadas, como o SO real faria
    /// (as rotas do túnel somem com a interface). Vazio = teardown completo.
    pub fn applied(&self) -> Vec<OsCall> {
        let mut live: Vec<OsCall> = Vec::new();
        for call in self.calls() {
            match call {
                OsCall::RemoveDns => live.retain(|c| !matches!(c, OsCall::SetDns { .. })),
                OsCall::RemoveGatewayRoute(g, _) => live.retain(|c| *c != OsCall::AddGatewayRoute(g)),
                // Mover não cria nem remove um /32 que já existe.
                OsCall::MoveGatewayRoute(g) => {
                    if !live.contains(&OsCall::AddGatewayRoute(g)) {
                        live.push(OsCall::AddGatewayRoute(g));
                    }
                }
                OsCall::Down => live.retain(|c| !matches!(c, OsCall::Up { .. } | OsCall::AddRoute(_))),
                added => live.push(added),
            }
        }
        live
    }

    fn record(&self, call: OsCall) {
        self.calls.lock().unwrap().push(call);
    }
}

impl Os for FakeOs {
    fn up(&self, ip: Ipv4Addr, peer: Ipv4Addr, mtu: u16, packets: Packets) -> Result<(), String> {
        self.record(OsCall::Up { ip, peer, mtu });
        *self.packets.lock().unwrap() = Some(packets);
        Ok(())
    }
    fn add_route(&self, route: Route) -> Result<(), String> {
        self.record(OsCall::AddRoute(route));
        match self.add_route {
            Failure::None => Ok(()),
            Failure::Error => Err("fake add_route failure".into()),
            Failure::Panic => panic!("fake add_route panic"),
        }
    }
    fn add_gateway_route(&self, gateway: IpAddr) -> Result<IpAddr, String> {
        self.record(OsCall::AddGatewayRoute(gateway));
        match self.add_gateway_route {
            Failure::None => Ok(FIRST_VIA),
            Failure::Error => Err("fake add_gateway_route failure".into()),
            Failure::Panic => panic!("fake add_gateway_route panic"),
        }
    }
    fn set_dns(&self, servers: &[Ipv4Addr], suffixes: &[String]) -> Result<(), String> {
        self.record(OsCall::SetDns { servers: servers.to_vec(), suffixes: suffixes.to_vec() });
        match self.set_dns {
            Failure::Error => Err("fake set_dns failure".into()),
            _ => Ok(()),
        }
    }
    fn remove_dns(&self) {
        self.record(OsCall::RemoveDns);
    }
    fn move_gateway_route(&self, gateway: IpAddr) -> Result<IpAddr, String> {
        if self.fail_next_move.swap(false, Ordering::SeqCst) {
            return Err("fake move_gateway_route failure".into());
        }
        self.record(OsCall::MoveGatewayRoute(gateway));
        Ok(NEW_VIA)
    }
    fn remove_gateway_route(&self, gateway: IpAddr, via: IpAddr) {
        self.record(OsCall::RemoveGatewayRoute(gateway, via));
    }
    fn state_file(&self) -> PathBuf {
        self.state_file.clone()
    }
    fn down(&self) {
        self.record(OsCall::Down);
        // Como fechar o fd do utun: o canal da interface acaba.
        self.packets.lock().unwrap().take();
    }
}

impl Drop for FakeOs {
    /// O arquivo de estado de um teste que falhou no meio não fica no diretório temporário.
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.state_file);
    }
}

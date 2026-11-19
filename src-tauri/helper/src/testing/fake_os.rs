//! Fake da camada de SO: registra cada chamada e guarda o canal de pacotes.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;

use crate::net::{Os, Packets, Route};

#[derive(Debug, Clone, PartialEq)]
pub enum OsCall {
    Up { ip: Ipv4Addr, peer: Ipv4Addr, mtu: u16 },
    AddRoute(Route),
    AddGatewayRoute(IpAddr),
    SetDns { servers: Vec<Ipv4Addr>, suffixes: Vec<String> },
    RemoveDns,
    RemoveGatewayRoute(IpAddr),
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

#[derive(Default)]
pub struct FakeOs {
    calls: Mutex<Vec<OsCall>>,
    packets: Mutex<Option<Packets>>,
    add_route: Failure,
}

impl FakeOs {
    /// Fake cujo `add_route` falha (erro ou pânico) depois de registrar a chamada.
    pub fn failing_add_route(failure: Failure) -> Self {
        Self { add_route: failure, ..Default::default() }
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
                OsCall::RemoveGatewayRoute(g) => live.retain(|c| *c != OsCall::AddGatewayRoute(g)),
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
    fn add_gateway_route(&self, gateway: IpAddr) -> Result<(), String> {
        self.record(OsCall::AddGatewayRoute(gateway));
        Ok(())
    }
    fn set_dns(&self, servers: &[Ipv4Addr], suffixes: &[String]) -> Result<(), String> {
        self.record(OsCall::SetDns { servers: servers.to_vec(), suffixes: suffixes.to_vec() });
        Ok(())
    }
    fn remove_dns(&self) {
        self.record(OsCall::RemoveDns);
    }
    fn remove_gateway_route(&self, gateway: IpAddr) {
        self.record(OsCall::RemoveGatewayRoute(gateway));
    }
    fn down(&self) {
        self.record(OsCall::Down);
        // Como fechar o fd do utun: o canal da interface acaba.
        self.packets.lock().unwrap().take();
    }
}

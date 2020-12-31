use crate::access_control_tree::ACTSocketAddress;
use crate::firewall_backend::FirewallBackend;
use chrono::Duration;
use std::net::IpAddr;
use tokio::macros::support::{Future, Pin};

pub struct NoopFirewallBackend {
    _priv: (),
}

impl NoopFirewallBackend {
    pub fn new() -> Self {
        log::info!("Firewall backend is disabled");
        Self { _priv: () }
    }
}

impl FirewallBackend for NoopFirewallBackend {
    fn add_temporary_allow_rule(
        &self,
        _client_ip_address: IpAddr,
        _destination_ip_address: IpAddr,
        _destination_socket: ACTSocketAddress,
        _ttl: Duration,
        _domain_name: &str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async {})
    }
}

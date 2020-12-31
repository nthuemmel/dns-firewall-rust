pub mod iptables;
pub mod noop;

use crate::access_control_tree::ACTSocketAddress;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;

pub trait FirewallBackend: Send + Sync {
    fn add_temporary_allow_rule<'a>(
        &'a self,
        client_ip_address: IpAddr,
        destination_ip_address: IpAddr,
        destination_socket: ACTSocketAddress,
        ttl: chrono::Duration,
        domain_name: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}

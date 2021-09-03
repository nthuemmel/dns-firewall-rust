pub mod iptables;
pub mod noop;

use crate::access_control_tree::ACTSocketAddress;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;

pub trait FirewallBackend: Send + Sync {
    /// Add a firewall allow rule from the given `client_ip_address` to the given
    /// `destination_ip_address`:`destination_socket` IP-protocol-port triple.
    /// The rule should stay valid only for the given `ttl`, and be removed afterwards.
    /// `domain_name` is not of importance for the firewall rule, but can be printed in diagnostic
    /// log messages or comments.
    /// The function should either return `Ok(())` on sucess, or `Err(())` on error.
    /// Errors should be logged internally.
    fn add_temporary_allow_rule<'a>(
        &'a self,
        client_ip_address: IpAddr,
        destination_ip_address: IpAddr,
        destination_socket: ACTSocketAddress,
        ttl: chrono::Duration,
        domain_name: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), ()>> + Send + 'a>>;
}

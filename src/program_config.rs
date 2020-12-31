use clap::arg_enum;
use std::net::IpAddr;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "dns-firewall")]
pub struct ProgramConfig {
    /// Path to the Access Control List (ACL) file
    #[structopt(long, env)]
    pub acl_file: PathBuf,

    #[structopt(flatten)]
    pub proxy_server: ProxyServerConfig,

    /// Firewall backend
    #[structopt(flatten)]
    pub firewall: FirewallConfig,
}

#[derive(Debug, StructOpt)]
pub struct ProxyServerConfig {
    /// IP address of the upstream server
    #[structopt(long, env)]
    pub upstream: IpAddr,

    /// Port of the upstream server
    #[structopt(long, env, default_value = "53")]
    pub upstream_port: u16,

    /// IP address to bind proxy server to
    #[structopt(long, env, default_value = "127.0.0.53")]
    pub bind: IpAddr,

    /// Port to bind proxy server to
    #[structopt(long, env, default_value = "537")]
    pub bind_port: u16,

    /// Maximum number of concurrent connections
    #[structopt(long, env, default_value = "100")]
    pub max_connections: u32,

    /// Connection timeout, in seconds
    #[structopt(long, env, default_value = "10")]
    pub timeout: u32,

    /// Minimum duration of firewall rules, in seconds; may override TTL
    #[structopt(long, env, default_value = "5")]
    pub min_rule_time: u32,

    /// Maximum duration of firewall rules, in seconds; may override TTL
    #[structopt(long, env)]
    pub max_rule_time: Option<u32>,
}

#[derive(Debug, StructOpt)]
pub struct FirewallConfig {
    /// Firewall backend
    #[structopt(long = "firewall", env = "FIREWALL", possible_values = &FirewallKind::variants(), case_insensitive = true)]
    pub backend: FirewallKind,

    /// Firewall chain (iptables backend only)
    #[structopt(long, env, required_if("backend", "iptables"))]
    pub chain: Option<String>,
}

arg_enum! {
    #[derive(Debug)]
    #[allow(non_camel_case_types)]
    pub enum FirewallKind {
        none,
        iptables,
    }
}

impl ProgramConfig {
    pub fn parse() -> Self {
        Self::from_args()
    }
}

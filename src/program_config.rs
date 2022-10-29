use clap::{Args, Parser, ValueEnum};
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[clap(name = "dns-firewall")]
pub struct ProgramConfig {
    /// Path to the Access Control List (ACL) file
    #[clap(long, env)]
    pub acl_file: PathBuf,

    #[clap(flatten)]
    pub proxy_server: ProxyServerConfig,

    /// Firewall backend
    #[clap(flatten)]
    pub firewall: FirewallConfig,
}

#[derive(Clone, Copy, Debug, Args)]
pub struct ProxyServerConfig {
    /// IP address of the upstream server
    #[clap(long, env)]
    pub upstream: IpAddr,

    /// Port of the upstream server
    #[clap(long, env, default_value = "53")]
    pub upstream_port: u16,

    /// IP address to bind proxy server to
    #[clap(long, env, default_value = "127.0.0.53")]
    pub bind: IpAddr,

    /// Port to bind proxy server to
    #[clap(long, env, default_value = "537")]
    pub bind_port: u16,

    /// Maximum number of concurrent connections
    #[clap(long, env, default_value = "100")]
    pub max_connections: u32,

    /// Connection timeout, in seconds
    #[clap(long, env, default_value = "10")]
    pub timeout: u32,

    /// Minimum duration of firewall rules, in seconds; may override TTL
    #[clap(long, env, default_value = "5")]
    pub min_rule_time: u32,

    /// Maximum duration of firewall rules, in seconds; may override TTL
    #[clap(long, env)]
    pub max_rule_time: Option<u32>,
}

#[derive(Debug, Args)]
pub struct FirewallConfig {
    /// Firewall backend
    #[clap(long = "firewall", env = "FIREWALL", value_enum, ignore_case = true)]
    pub backend: FirewallKind,

    /// Firewall chain (iptables backend only)
    #[clap(long, env, required_if_eq("backend", "iptables"))]
    pub chain: Option<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
#[allow(non_camel_case_types)]
pub enum FirewallKind {
    none,
    iptables,
}

impl ProgramConfig {
    pub fn parse() -> Self {
        Parser::parse()
    }
}

use std::net::IpAddr;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "dns-firewall")]
pub struct ProgramOptions {
    /// Path to the Access Control List (ACL) file
    #[structopt(long)]
    pub acl_file: PathBuf,

    #[structopt(flatten)]
    pub proxy_server: ProxyServerSettings,

    /// Firewall backend
    #[structopt(subcommand)]
    pub firewall: Firewall,
}

#[derive(Debug, StructOpt)]
pub struct ProxyServerSettings {
    /// IP address of the upstream server
    #[structopt(long)]
    pub upstream: IpAddr,

    /// Port of the upstream server
    #[structopt(long, default_value = "53")]
    pub upstream_port: u16,

    /// IP address to bind proxy server to
    #[structopt(long, default_value = "127.0.0.53")]
    pub bind: IpAddr,

    /// Port to bind proxy server to
    #[structopt(long, default_value = "537")]
    pub bind_port: u16,

    /// Maximum number of concurrent connections
    #[structopt(long, default_value = "100")]
    pub max_connections: u32,

    /// Connection timeout, in seconds
    #[structopt(long, default_value = "10")]
    pub timeout: u32,

    /// Minimum duration of firewall rules, in seconds; may override TTL
    #[structopt(long, default_value = "5")]
    pub min_rule_time: u32,

    /// Maximum duration of firewall rules, in seconds; may override TTL
    #[structopt(long)]
    pub max_rule_time: Option<u32>,
}

#[derive(Debug, StructOpt)]
pub enum Firewall {
    /// Start without firewall integration (for testing purposes)
    NoFirewall,

    /// Start with iptables as firewall backend
    Iptables {
        /// Firewall chain
        #[structopt(long)]
        chain: String,
    },
}

impl ProgramOptions {
    pub fn parse() -> Self {
        Self::from_args()
    }
}

use crate::access_control_tree::SocketAddress;
use crate::firewall_backend::FirewallBackend;
use anyhow::bail;
use chrono::Duration;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;

const IPTABLES: &str = "/usr/sbin/iptables";
const IP6TABLES: &str = "/usr/sbin/ip6tables";
const IPSET: &str = "/usr/sbin/ipset";
const IP4_SET_SUFFIX: &str = "-ipv4-allow";
const IP6_SET_SUFFIX: &str = "-ipv6-allow";
const IP4_LOCAL_SET_SUFFIX: &str = "-ipv4-allow-local";
const IP6_LOCAL_SET_SUFFIX: &str = "-ipv6-allow-local";

pub struct IptablesFirewallBackend {
    chain_name: String,
    ipv4_enabled: bool,
    ipv6_enabled: bool,
}

impl IptablesFirewallBackend {
    pub fn new(chain_name: String) -> anyhow::Result<Self> {
        log::info!("Using iptables backend, chain \"{}\"", chain_name);

        // Note: Default set timeout does not matter, we specify timeout for each entry individually

        // We use `ipset`s to allow src -> dst connections, because it hast neat built-in whitelist support.
        // We need 4 sets: IPv4, IPv6, and IPv4/IPv6 for local (connections originating from localhost).
        // Connections originating from localhost are a special case because name resolution usually happens via loopback (127.0.0.1),
        // but outgoing connections use the source address of the corresponding interface (!= 127.0.0.1),
        // therefore we use `--src-type local`, which requires additional sets.

        let enable_ipv4 = Self::run_process_sync(IPTABLES, &["-F", &chain_name]).is_ok();

        if enable_ipv4 {
            Self::run_process_sync(
                IPSET,
                &[
                    "create",
                    &format!("{}{}", chain_name, IP4_SET_SUFFIX),
                    "hash:ip,port,ip",
                    "timeout",
                    "60",
                    "comment",
                    "-exist",
                ],
            )?;
            Self::run_process_sync(
                IPSET,
                &[
                    "create",
                    &format!("{}{}", chain_name, IP4_LOCAL_SET_SUFFIX),
                    "hash:ip,port",
                    "timeout",
                    "60",
                    "comment",
                    "-exist",
                ],
            )?;
            Self::run_process_sync(
                IPTABLES,
                &[
                    "-A",
                    &chain_name,
                    "-m",
                    "set",
                    "--match-set",
                    &format!("{}{}", chain_name, IP4_SET_SUFFIX),
                    "src,dst,dst",
                    "-j",
                    "ACCEPT",
                ],
            )?;
            Self::run_process_sync(
                IPTABLES,
                &[
                    "-A",
                    &chain_name,
                    "-m",
                    "addrtype",
                    "--src-type",
                    "local",
                    "-m",
                    "set",
                    "--match-set",
                    &format!("{}{}", chain_name, IP4_LOCAL_SET_SUFFIX),
                    "dst,dst",
                    "-j",
                    "ACCEPT",
                ],
            )?;
        } else {
            log::warn!("No IPv4 rules will be created.");
        }

        let enable_ipv6 = Self::run_process_sync(IP6TABLES, &["-F", &chain_name]).is_ok();

        if enable_ipv6 {
            Self::run_process_sync(
                IPSET,
                &[
                    "create",
                    &format!("{}{}", chain_name, IP6_SET_SUFFIX),
                    "hash:ip,port,ip",
                    "timeout",
                    "60",
                    "comment",
                    "family",
                    "inet6",
                    "-exist",
                ],
            )?;
            Self::run_process_sync(
                IPSET,
                &[
                    "create",
                    &format!("{}{}", chain_name, IP6_LOCAL_SET_SUFFIX),
                    "hash:ip,port",
                    "timeout",
                    "60",
                    "comment",
                    "family",
                    "inet6",
                    "-exist",
                ],
            )?;
            Self::run_process_sync(
                IP6TABLES,
                &[
                    "-A",
                    &chain_name,
                    "-m",
                    "set",
                    "--match-set",
                    &format!("{}{}", chain_name, IP6_SET_SUFFIX),
                    "src,dst,dst",
                    "-j",
                    "ACCEPT",
                ],
            )?;
            Self::run_process_sync(
                IP6TABLES,
                &[
                    "-A",
                    &chain_name,
                    "-m",
                    "addrtype",
                    "--src-type",
                    "local",
                    "-m",
                    "set",
                    "--match-set",
                    &format!("{}{}", chain_name, IP6_LOCAL_SET_SUFFIX),
                    "dst,dst",
                    "-j",
                    "ACCEPT",
                ],
            )?;
        } else {
            log::warn!("No IPv6 rules will be created.");
        }

        if !enable_ipv4 && !enable_ipv6 {
            bail!("Neither IPv4 nor IPv6 can be used, aborting");
        }

        Ok(Self {
            chain_name,
            ipv4_enabled: enable_ipv4,
            ipv6_enabled: enable_ipv6,
        })
    }

    fn run_process_sync(program: &str, args: &[&str]) -> anyhow::Result<()> {
        Self::handle_process_output(
            program,
            args,
            std::process::Command::new(program).args(args).output(),
        )
    }

    async fn run_process_async(program: &str, args: &[&str]) -> Result<(), ()> {
        Self::handle_process_output(
            program,
            args,
            tokio::process::Command::new(program)
                .args(args)
                .output()
                .await,
        )
        .map_err(|_| ())
    }

    fn handle_process_output(
        program: &str,
        args: &[&str],
        output: std::io::Result<std::process::Output>,
    ) -> anyhow::Result<()> {
        match output {
            Ok(output) => {
                if output.status.success() {
                    return Ok(());
                } else {
                    log::error!(
                        "'{} {}' failed: [{}] {}",
                        program,
                        args.join(" "),
                        output.status,
                        String::from_utf8_lossy(&output.stderr).trim_end()
                    );
                }
            }
            Err(e) => {
                log::error!("Failed to start {}: {}", program, e);
            }
        }

        bail!("Failed to run {}", program);
    }
}

impl FirewallBackend for IptablesFirewallBackend {
    fn add_temporary_allow_rule<'a>(
        &'a self,
        client_ip_address: IpAddr,
        destination_ip_address: IpAddr,
        destination_socket: SocketAddress,
        ttl: Duration,
        domain_name: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), ()>> + Send + 'a>> {
        Box::pin(async move {
            if client_ip_address.is_loopback() {
                // In case the client is localhost, we add *both* IPv4 and IPv6 rules whenever possible
                if self.ipv4_enabled && destination_ip_address.is_ipv4() {
                    Self::run_process_async(
                        IPSET,
                        &[
                            "add",
                            &format!("{}{}", self.chain_name, IP4_LOCAL_SET_SUFFIX),
                            &format!(
                                "{},{}:{}",
                                destination_ip_address,
                                destination_socket.protocol.number(), // Don't use protocol name, /etc/protocols may not be read by all systems (e.g. OpenWRT)
                                destination_socket.port
                            ),
                            "timeout",
                            &ttl.num_seconds().to_string(),
                            "comment",
                            domain_name,
                            "-exist",
                        ],
                    )
                    .await?;
                }

                if self.ipv6_enabled {
                    let ip6 = match destination_ip_address {
                        IpAddr::V4(ip4) => ip4.to_ipv6_mapped(),
                        IpAddr::V6(ip6) => ip6,
                    };

                    Self::run_process_async(
                        IPSET,
                        &[
                            "add",
                            &format!("{}{}", self.chain_name, IP6_LOCAL_SET_SUFFIX),
                            &format!(
                                "{},{}:{}",
                                ip6,
                                destination_socket.protocol.number(), // Don't use protocol name, /etc/protocols may not be read by all systems (e.g. OpenWRT)
                                destination_socket.port
                            ),
                            "timeout",
                            &ttl.num_seconds().to_string(),
                            "comment",
                            domain_name,
                            "-exist",
                        ],
                    )
                    .await?;
                }
            } else if (client_ip_address.is_ipv4() && self.ipv4_enabled)
                || (client_ip_address.is_ipv6() && self.ipv6_enabled)
            {
                let set_name = format!(
                    "{}{}",
                    self.chain_name,
                    if client_ip_address.is_ipv6() {
                        IP6_SET_SUFFIX
                    } else {
                        IP4_SET_SUFFIX
                    }
                );

                Self::run_process_async(
                    IPSET,
                    &[
                        "add",
                        &set_name,
                        &format!(
                            "{},{}:{},{}",
                            client_ip_address,
                            destination_socket.protocol.number(), // Don't use protocol name, /etc/protocols may not be read by all systems (e.g. OpenWRT)
                            destination_socket.port,
                            destination_ip_address,
                        ),
                        "timeout",
                        &ttl.num_seconds().to_string(),
                        "comment",
                        domain_name,
                        "-exist",
                    ],
                )
                .await?;
            }

            Ok(())
        })
    }
}

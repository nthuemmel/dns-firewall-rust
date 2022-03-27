use crate::access_control_tree::builder::AccessControlTreeBuilder;
use crate::access_control_tree::{
    AccessControlTree, AllowRule, BlockRule, DomainNamePattern, Rule, SocketAddress,
};
use crate::protocol::Protocol;
use anyhow::Context;
use anyhow::{anyhow, bail};
use ipnet::IpNet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

pub fn parse_file(file_path: &Path) -> anyhow::Result<AccessControlTree> {
    let file = File::open(file_path)?;
    parse_input(BufReader::new(file))
}

fn parse_input(reader: impl BufRead) -> anyhow::Result<AccessControlTree> {
    let mut tree_builder = AccessControlTreeBuilder::new();

    for (line_number, line) in reader.lines().enumerate() {
        let line = line.with_context(|| format!("Failed to read line {}", line_number))?;
        process_line(line_number, &line, &mut tree_builder)
            .with_context(|| format!("Failed to process line {}: {}", line_number, line))?;
    }

    Ok(tree_builder.build())
}

fn process_line(
    line_number: usize,
    line: &str,
    tree_builder: &mut AccessControlTreeBuilder,
) -> anyhow::Result<()> {
    let line = line.split('#').next().unwrap().trim(); // Ignore comment part

    if line.is_empty() {
        // This is a comment or empty line
        return Ok(());
    }

    // Try to parse: [client IP address or subnet (CIDR)] -> [domain]:[protocol]:[port]
    let tokens = line.split("->").collect::<Vec<_>>();
    if tokens.len() == 2 {
        let client_address = tokens[0].trim();

        // Parse destination triple
        let destination = tokens[1].trim();
        let destination_tokens = destination.split(':').collect::<Vec<_>>();
        if destination_tokens.len() != 3 {
            bail!("Invalid destination '{}': Expected a 'domain:protocol:port' triple, e.g. 'google.com:tcp:443'", destination);
        }

        // Parse domain name
        let domain_name = destination_tokens[0].trim();
        let domain_name = DomainNamePattern::parse(domain_name)
            .with_context(|| format!("'{}' is not a valid domain name pattern", domain_name))?;

        // Parse protocol
        let protocol_str = destination_tokens[1].trim();
        let protocol = Protocol::parse(protocol_str)
            .ok_or_else(|| anyhow!("Unknown protocol '{}'", protocol_str))?;

        // Parse port
        let port_str = destination_tokens[2].trim();
        let port =
            u16::from_str(port_str).with_context(|| format!("Invalid port '{}'", port_str))?;

        // Parse client address & insert ACT entry
        let client_subnet = parse_client_subnet(client_address)?;

        insert_rule(
            tree_builder,
            client_subnet,
            domain_name,
            Rule::Allow(AllowRule::for_destination_socket(SocketAddress {
                protocol,
                port,
            })),
            line_number,
        )?;

        return Ok(());
    }

    // Try to parse: [client IP address or subnet (CIDR)] ~> [domain]
    let tokens = line.split("~>").collect::<Vec<_>>();
    if tokens.len() == 2 {
        let client_address = tokens[0].trim();

        // Parse domain name
        let domain_name = tokens[1].trim();
        let domain_name = DomainNamePattern::parse(domain_name)
            .with_context(|| format!("'{}' is not a valid domain name pattern", domain_name))?;

        // Parse client address & insert ACT entry
        let client_subnet = parse_client_subnet(client_address)?;

        if domain_name == DomainNamePattern::Any {
            tree_builder.allow_all_dns_queries(client_subnet);
        } else {
            insert_rule(
                tree_builder,
                client_subnet,
                domain_name,
                Rule::Allow(AllowRule::for_all_dns_questions()),
                line_number,
            )?;
        }

        return Ok(());
    }

    let tokens = line.split("-|").collect::<Vec<_>>();
    if tokens.len() == 2 {
        let client_address = tokens[0].trim();

        // Parse destination
        let destination = tokens[1].trim();
        let destination_tokens = destination.split('=').collect::<Vec<_>>();

        let (domain_name, rule) = match destination_tokens.len() {
            1 => (destination, BlockRule::RefuseDnsQuery),
            2 => {
                let domain_name = destination_tokens[0].trim();

                let ip_addr = destination_tokens[1].trim();
                let ip_addr = IpAddr::from_str(ip_addr).with_context(|| {
                    format!(
                        "Could not parse IP address '{}' - expected an IPv4 or IPv6 address",
                        ip_addr
                    )
                })?;

                (domain_name, BlockRule::ResolveToStaticIp(ip_addr))
            }
            _ => {
                bail!(
                    "Invalid destination '{}': Expected either 'domain' or 'domain = IP address'",
                    destination
                );
            }
        };

        // Parse domain name
        let domain_name = DomainNamePattern::parse(domain_name)
            .with_context(|| format!("'{}' is not a valid domain name pattern", domain_name))?;

        // Parse client address & insert ACT entry
        let client_subnet = parse_client_subnet(client_address)?;

        insert_rule(
            tree_builder,
            client_subnet,
            domain_name,
            Rule::Block(rule),
            line_number,
        )?;

        return Ok(());
    }

    bail!("Invalid format: Expected one of\n'[client IP address or subnet (CIDR)] -> [domain]:[protocol]:[port]' or\n'[client IP address or subnet (CIDR)] ~> [domain]' or\n'[client IP address or subnet (CIDR)] -| [domain]' or\n'[client IP address or subnet (CIDR)] -| [domain] = [IP address]'");
}

fn parse_client_subnet(client_address: &str) -> anyhow::Result<IpNet> {
    // The IpNet parser requires CIDR notation (i.e. trailing /<masklen>)
    // If the user didn't specify a mask, we take care of it.
    let client_subnet = if client_address.contains('/') {
        IpNet::from_str(client_address).map_err(anyhow::Error::from)
    } else {
        IpAddr::from_str(client_address)
            .map(IpNet::from)
            .map_err(anyhow::Error::from)
    }
    .with_context(|| {
        format!(
            "Could not parse client IP address '{}' - expected an IPv4 or \
    		 IPv6 address or subnet in CIDR notation",
            client_address
        )
    })?;

    Ok(client_subnet)
}

fn insert_rule(
    tree_builder: &mut AccessControlTreeBuilder,
    client_subnet: IpNet,
    domain_name: DomainNamePattern,
    rule: Rule,
    line_number: usize,
) -> anyhow::Result<()> {
    let rule_kind = rule.kind();
    let domain_name_str = domain_name.to_string();

    tree_builder
        .insert_rule(client_subnet, domain_name, rule, line_number)
        .with_context(|| {
            format!(
                "Could not insert {} rule for domain name pattern '{}' in client subnet {}",
                rule_kind, domain_name_str, client_subnet
            )
        })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::access_control_tree::*;
    use crate::protocol::Protocol;
    use ipnet::IpNet;
    use std::net::IpAddr;
    use std::str::FromStr;

    fn parse(input: &str) -> AccessControlTree {
        parse_input(input.as_bytes()).unwrap()
    }

    #[test]
    fn exhaustive_example() {
        let input = r#"
# Some comment
192.168.4.0/24 ~> mail.local
192.168.4.0/24 -> r3.o.lencr.org:TCP:80					# Let's Encrypt OCSP responder
2001:0db8:85a3:0000:0000:8a2e:0370:7334 -> example.com:TCP:22

10.34.3.0/16 -> example.local:UDP:3478
10.34.3.0/16 ~> *.matrix.org
10.3.4.5 ~> *
192.168.1.1 -> service.local:tcp:443
192.168.1.1 -> service.local:udp:333
192.168.1.1 -> *.matrix.org:TCP:443
192.168.1.1 -> *:TCP:22
   # huh

192.168.4.1 -| r3.o.lencr.org
10.34.1.1/24 -| subdomain.matrix.org = 127.0.0.1
"#;
        let act = parse(input);

        let expected_entries = vec![
            (
                IpAddr::from_str("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
                    .unwrap()
                    .into(),
                SubnetConfiguration {
                    allow_all_dns_queries: false,
                    sorted_rules: vec![(
                        DomainNamePattern::Exact {
                            fqdn: "example.com.".to_string(),
                        },
                        Rule::Allow(AllowRule {
                            allow_all_dns_questions: false,
                            allowed_destination_sockets: vec![SocketAddress {
                                protocol: Protocol::Tcp,
                                port: 22,
                            }],
                        }),
                    )],
                },
            ),
            (
                IpAddr::from_str("192.168.4.1").unwrap().into(),
                SubnetConfiguration {
                    allow_all_dns_queries: false,
                    sorted_rules: vec![(
                        DomainNamePattern::Exact {
                            fqdn: "r3.o.lencr.org.".to_string(),
                        },
                        Rule::Block(BlockRule::RefuseDnsQuery),
                    )],
                },
            ),
            (
                IpAddr::from_str("192.168.1.1").unwrap().into(),
                SubnetConfiguration {
                    allow_all_dns_queries: false,
                    sorted_rules: vec![
                        (
                            DomainNamePattern::Exact {
                                fqdn: "service.local.".to_string(),
                            },
                            Rule::Allow(AllowRule {
                                allow_all_dns_questions: false,
                                allowed_destination_sockets: vec![
                                    SocketAddress {
                                        protocol: Protocol::Tcp,
                                        port: 443,
                                    },
                                    SocketAddress {
                                        protocol: Protocol::Udp,
                                        port: 333,
                                    },
                                ],
                            }),
                        ),
                        (
                            DomainNamePattern::AllSubdomainsOf {
                                fqdn_tail: ".matrix.org.".to_string(),
                            },
                            Rule::Allow(AllowRule {
                                allow_all_dns_questions: false,
                                allowed_destination_sockets: vec![SocketAddress {
                                    protocol: Protocol::Tcp,
                                    port: 443,
                                }],
                            }),
                        ),
                        (
                            DomainNamePattern::Any,
                            Rule::Allow(AllowRule {
                                allow_all_dns_questions: false,
                                allowed_destination_sockets: vec![SocketAddress {
                                    protocol: Protocol::Tcp,
                                    port: 22,
                                }],
                            }),
                        ),
                    ],
                },
            ),
            (
                IpAddr::from_str("10.3.4.5").unwrap().into(),
                SubnetConfiguration {
                    allow_all_dns_queries: true,
                    sorted_rules: vec![],
                },
            ),
            (
                IpNet::from_str("192.168.4.0/24").unwrap(),
                SubnetConfiguration {
                    allow_all_dns_queries: false,
                    sorted_rules: vec![
                        (
                            DomainNamePattern::Exact {
                                fqdn: "r3.o.lencr.org.".to_string(),
                            },
                            Rule::Allow(AllowRule {
                                allow_all_dns_questions: false,
                                allowed_destination_sockets: vec![SocketAddress {
                                    protocol: Protocol::Tcp,
                                    port: 80,
                                }],
                            }),
                        ),
                        (
                            DomainNamePattern::Exact {
                                fqdn: "mail.local.".to_string(),
                            },
                            Rule::Allow(AllowRule {
                                allow_all_dns_questions: true,
                                allowed_destination_sockets: vec![],
                            }),
                        ),
                    ],
                },
            ),
            (
                IpNet::from_str("10.34.1.1/24").unwrap(),
                SubnetConfiguration {
                    allow_all_dns_queries: false,
                    sorted_rules: vec![(
                        DomainNamePattern::Exact {
                            fqdn: "subdomain.matrix.org.".to_string(),
                        },
                        Rule::Block(BlockRule::ResolveToStaticIp(
                            IpAddr::from_str("127.0.0.1").unwrap(),
                        )),
                    )],
                },
            ),
            (
                IpNet::from_str("10.34.3.0/16").unwrap(),
                SubnetConfiguration {
                    allow_all_dns_queries: false,
                    sorted_rules: vec![
                        (
                            DomainNamePattern::Exact {
                                fqdn: "example.local.".to_string(),
                            },
                            Rule::Allow(AllowRule {
                                allow_all_dns_questions: false,
                                allowed_destination_sockets: vec![SocketAddress {
                                    protocol: Protocol::Udp,
                                    port: 3478,
                                }],
                            }),
                        ),
                        (
                            DomainNamePattern::AllSubdomainsOf {
                                fqdn_tail: ".matrix.org.".to_string(),
                            },
                            Rule::Allow(AllowRule {
                                allow_all_dns_questions: true,
                                allowed_destination_sockets: vec![],
                            }),
                        ),
                    ],
                },
            ),
        ];

        assert_eq!(act.take_entries(), expected_entries);
    }

    #[test]
    #[should_panic(
        expected = "Invalid destination 'dest.local:TCP': Expected a 'domain:protocol:port' triple"
    )]
    fn target_triple_too_short() {
        parse("192.168.1.1 -> dest.local:TCP");
    }

    #[test]
    #[should_panic(
        expected = "Invalid destination 'dest.local:TCP:80:80': Expected a 'domain:protocol:port' triple"
    )]
    fn target_triple_too_long() {
        parse("192.168.1.1 -> dest.local:TCP:80:80");
    }

    #[test]
    #[should_panic(expected = "Unknown protocol 'SLURP'")]
    fn unknown_protocol() {
        parse("192.168.1.1 -> dest.local:SLURP:80");
    }

    #[test]
    #[should_panic(expected = "Invalid port 'foo'")]
    fn invalid_port() {
        parse("192.168.1.1 -> dest.local:TCP:foo");
    }

    #[test]
    #[should_panic(expected = "Invalid format: Expected one of")]
    fn invalid_format() {
        parse("192.168.1.1 |> dest.local:TCP:80");
    }

    #[test]
    #[should_panic(expected = "invalid IP address syntax")]
    fn invalid_ip() {
        parse("xfoo -> dest.local:TCP:80");
    }

    #[test]
    #[should_panic(
        expected = "Wildcards (*) may only appear at the beginning in place of a subdomain"
    )]
    fn invalid_wildcard_beginning() {
        parse("192.168.1.1 -> *foo.bar:TCP:80");
    }

    #[test]
    #[should_panic(
        expected = "Wildcards (*) may only appear at the beginning in place of a subdomain"
    )]
    fn invalid_wildcard_middle() {
        parse("192.168.1.1 -> foo*bar:TCP:80");
    }

    #[test]
    #[should_panic(
        expected = "Invalid destination 'dest.local = 127.0.0.1 = foo': Expected either 'domain' or 'domain = IP address'"
    )]
    fn invalid_block_rule() {
        parse("192.168.1.1 -| dest.local = 127.0.0.1 = foo");
    }

    #[test]
    #[should_panic(
        expected = "Could not parse IP address '127.0.0.1/24' - expected an IPv4 or IPv6 address"
    )]
    fn invalid_block_rule_ip() {
        parse("192.168.1.1 -| dest.local = 127.0.0.1/24");
    }

    #[test]
    #[should_panic(expected = "'dest.*.local' is not a valid domain name pattern")]
    fn invalid_block_rule_domain() {
        parse("192.168.1.1 -| dest.*.local = 127.0.0.1");
    }
}

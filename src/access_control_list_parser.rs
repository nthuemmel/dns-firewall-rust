use crate::access_control_tree::{
    ACTSocketAddress, ACTSubnet, AccessControlTree, AccessControlTreeBuilder,
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
        process_line(&line, &mut tree_builder)
            .with_context(|| format!("Failed to process line {}: {}", line_number, line))?;
    }

    Ok(tree_builder.build())
}

fn process_line(line: &str, tree_builder: &mut AccessControlTreeBuilder) -> anyhow::Result<()> {
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
        let domain_name = destination_tokens[0].trim().to_string();

        // Parse protocol
        let protocol_str = destination_tokens[1].trim();
        let protocol = Protocol::parse(protocol_str)
            .ok_or_else(|| anyhow!("Unknown protocol '{}'", protocol_str))?;

        // Parse port
        let port_str = destination_tokens[2].trim();
        let port =
            u16::from_str(port_str).with_context(|| format!("Invalid port '{}'", port_str))?;

        // Parse client address & insert ACT entry
        insert_act_entry(tree_builder, client_address, |entry| {
            entry
                .domain_name_map
                .entry(domain_name)
                .or_default()
                .allowed_destination_sockets
                .push(ACTSocketAddress { protocol, port });
        })?;

        return Ok(());
    }

    // Try to parse: [client IP address or subnet (CIDR)] ~> [domain]
    let tokens = line.split("~>").collect::<Vec<_>>();
    if tokens.len() == 2 {
        let client_address = tokens[0].trim();

        // Parse domain name
        let domain_name = tokens[1].trim().to_string();

        // Parse client address & insert ACT entry
        insert_act_entry(tree_builder, client_address, |entry| {
            if domain_name == "*" {
                entry.allow_all_dns_queries = true;
            } else {
                entry
                    .domain_name_map
                    .entry(domain_name)
                    .or_default()
                    .allow_all_dns_questions = true;
            }
        })?;

        return Ok(());
    }

    bail!("Invalid format: Expected '[client IP address or subnet (CIDR)] -> [domain]:[protocol]:[port]' or '[client IP address or subnet (CIDR)] ~> [domain]'");
}

fn insert_act_entry(
    tree_builder: &mut AccessControlTreeBuilder,
    client_address: &str,
    entry_modifier: impl FnOnce(&mut ACTSubnet),
) -> anyhow::Result<()> {
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

    entry_modifier(tree_builder.entry(client_subnet));

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::access_control_tree::{ACTDomain, ACTSocketAddress, ACTSubnet, AccessControlTree};
    use crate::protocol::Protocol;
    use ipnet::IpNet;
    use maplit::hashmap;
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

10.34.3.3 -> example.local:UDP:3478
10.3.4.5 ~> *
192.168.1.1 -> service.local:tcp:443
192.168.1.1 -> service.local:udp:333
   # huh
"#;
        let act = parse(input);

        let expected_entries = hashmap! {
            IpNet::from_str("192.168.4.0/24").unwrap() => ACTSubnet {
                allow_all_dns_queries: false,
                domain_name_map: hashmap! {
                    "mail.local".to_string() => ACTDomain {
                        allow_all_dns_questions: true,
                        allowed_destination_sockets: vec![],
                    },
                    "r3.o.lencr.org".to_string() => ACTDomain {
                        allow_all_dns_questions: false,
                        allowed_destination_sockets: vec![
                            ACTSocketAddress {
                                protocol: Protocol::Tcp,
                                port: 80,
                            }
                        ]
                    }
                },
            },
            IpAddr::from_str("2001:0db8:85a3:0000:0000:8a2e:0370:7334").unwrap().into() => ACTSubnet {
                allow_all_dns_queries: false,
                domain_name_map: hashmap! {
                    "example.com".to_string() => ACTDomain {
                        allow_all_dns_questions: false,
                        allowed_destination_sockets: vec![
                            ACTSocketAddress {
                                protocol: Protocol::Tcp,
                                port: 22,
                            }
                        ]
                    }
                },
            },
            IpAddr::from_str("10.34.3.3").unwrap().into() => ACTSubnet {
                allow_all_dns_queries: false,
                domain_name_map: hashmap! {
                    "example.local".to_string() => ACTDomain {
                        allow_all_dns_questions: false,
                        allowed_destination_sockets: vec![
                            ACTSocketAddress {
                                protocol: Protocol::Udp,
                                port: 3478,
                            }
                        ]
                    }
                },
            },
            IpAddr::from_str("10.3.4.5").unwrap().into() => ACTSubnet {
                allow_all_dns_queries: true,
                domain_name_map: hashmap! {},
            },
            IpAddr::from_str("192.168.1.1").unwrap().into() => ACTSubnet {
                allow_all_dns_queries: false,
                domain_name_map: hashmap! {
                    "service.local".to_string() => ACTDomain {
                        allow_all_dns_questions: false,
                        allowed_destination_sockets: vec![
                            ACTSocketAddress {
                                protocol: Protocol::Tcp,
                                port: 443,
                            },
                            ACTSocketAddress {
                                protocol: Protocol::Udp,
                                port: 333,
                            }
                        ]
                    }
                },
            },
        };

        assert_eq!(act.into_map(), expected_entries);
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
    #[should_panic(
        expected = "Invalid format: Expected '[client IP address or subnet (CIDR)] -> [domain]:[protocol]:[port]' or '[client IP address or subnet (CIDR)] ~> [domain]'"
    )]
    fn invalid_format() {
        parse("192.168.1.1 |> dest.local:TCP:80");
    }

    #[test]
    #[should_panic(expected = "invalid IP address syntax")]
    fn invalid_ip() {
        parse("xfoo -> dest.local:TCP:80");
    }
}

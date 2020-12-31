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
    let reader = BufReader::new(file);
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
        let domain_name = destination_tokens[0].to_string();

        // Parse protocol
        let protocol = Protocol::parse(destination_tokens[1])
            .ok_or_else(|| anyhow!("Unknown protocol '{}'", destination_tokens[1]))?;

        // Parse port
        let port = u16::from_str(destination_tokens[2])
            .with_context(|| format!("Invalid port '{}'", destination_tokens[2]))?;

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
        let domain_name = tokens[1].to_string();

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

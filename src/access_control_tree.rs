use crate::protocol::Protocol;
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::IpAddr;

pub struct AccessControlTree {
    entries: Vec<(IpNet, ACTSubnet)>,
}

#[derive(Default)]
pub struct ACTSubnet {
    pub allow_all_dns_queries: bool,
    pub domain_name_map: HashMap<String, ACTDomain>,
}

#[derive(Default)]
pub struct ACTDomain {
    pub allow_all_dns_questions: bool,
    pub allowed_destination_sockets: Vec<ACTSocketAddress>,
}

#[derive(Clone, Copy)]
pub struct ACTSocketAddress {
    pub protocol: Protocol,
    pub port: u16,
}

pub struct AccessControlTreeBuilder {
    entries: HashMap<IpNet, ACTSubnet>,
}

impl AccessControlTree {
    pub fn get_matching_entries(&self, client_ip_address: IpAddr) -> Vec<&ACTSubnet> {
        self.entries
            .iter()
            .filter(|(net, _)| net.contains(&client_ip_address))
            .map(|(_, v)| v)
            .collect()
    }
}

impl AccessControlTreeBuilder {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn entry(&mut self, client_subnet: IpNet) -> &mut ACTSubnet {
        self.entries.entry(client_subnet).or_default()
    }

    pub fn build(self) -> AccessControlTree {
        AccessControlTree {
            entries: self.entries.into_iter().collect(),
        }
    }
}

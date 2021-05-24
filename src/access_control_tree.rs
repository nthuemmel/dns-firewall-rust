use crate::protocol::Protocol;
use anyhow::bail;
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, PartialEq)]
pub struct AccessControlTree {
    entries: Vec<(IpNet, ACTSubnet)>,
}

#[derive(Debug, Default, PartialEq)]
pub struct ACTSubnet {
    pub allow_all_dns_queries: bool,
    pub domains: Vec<ACTDomain>,
}

#[derive(Debug, PartialEq)]
pub struct ACTDomain {
    pub name: DomainNamePattern,
    pub allow_all_dns_questions: bool,
    pub allowed_destination_sockets: Vec<ACTSocketAddress>,
}

#[derive(Debug, PartialEq)]
pub enum DomainNamePattern {
    Any,
    Exact {
        fqdn: String,
    },
    AllSubdomainsOf {
        /// Must start with a dot
        fqdn_tail: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq)]
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

    #[cfg(test)]
    pub fn into_map(self) -> HashMap<IpNet, ACTSubnet> {
        self.entries.into_iter().collect()
    }
}

impl ACTSubnet {
    pub fn get_or_create_domain_entry(&mut self, name: DomainNamePattern) -> &mut ACTDomain {
        // See https://stackoverflow.com/questions/58249193/how-to-find-or-insert-into-a-vec-in-rust
        // for why using indices is necessary here
        for i in 0..self.domains.len() {
            if self.domains[i].name == name {
                return &mut self.domains[i];
            }
        }

        self.domains.push(ACTDomain {
            name,
            allow_all_dns_questions: false,
            allowed_destination_sockets: Vec::new(),
        });
        self.domains.last_mut().unwrap()
    }
}

impl DomainNamePattern {
    pub fn parse(input: &str) -> anyhow::Result<Self> {
        if input == "*" {
            Ok(Self::Any)
        } else if input.starts_with("*.") {
            Ok(Self::AllSubdomainsOf {
                fqdn_tail: input[1..].to_string(),
            })
        } else if input.contains('*') {
            bail!(
                "Wildcards (*) may only appear at the beginning \
                 in place of a subdomain (e.g. '*.example.local')"
            );
        } else {
            Ok(Self::Exact {
                fqdn: input.to_string(),
            })
        }
    }

    pub fn matches(&self, against_fqdn: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Exact { fqdn } => fqdn == against_fqdn,
            Self::AllSubdomainsOf { fqdn_tail } => against_fqdn.ends_with(fqdn_tail),
        }
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

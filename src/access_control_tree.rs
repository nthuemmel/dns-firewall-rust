pub mod builder;
pub mod matcher;

use crate::access_control_tree::matcher::SubnetMatcher;
use crate::protocol::Protocol;
use anyhow::bail;
use ipnet::IpNet;
use std::net::IpAddr;

#[derive(Debug, PartialEq, Eq)]
pub struct AccessControlTree {
    /// Entries are sorted by specificity: Most specific subnet (longest prefix) comes first,
    /// least specific last
    sorted_entries: Vec<(IpNet, SubnetConfiguration)>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct SubnetConfiguration {
    pub allow_all_dns_queries: bool,

    /// Entries are sorted by specificity: Most specific domain (longest match) comes first,
    /// least specific last
    pub sorted_rules: Vec<(DomainNamePattern, Rule)>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DomainNamePattern {
    Any,
    Exact {
        /// Must end with a dot
        fqdn: String,
    },
    AllSubdomainsOf {
        /// Must start with a dot and end with a dot
        fqdn_tail: String,
    },
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Rule {
    Allow(AllowRule),
    Block(BlockRule),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AllowRule {
    pub allow_all_dns_questions: bool,
    pub allowed_destination_sockets: Vec<SocketAddress>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockRule {
    RefuseDnsQuery,
    ResolveToStaticIp(IpAddr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketAddress {
    pub protocol: Protocol,
    pub port: u16,
}

impl AccessControlTree {
    pub fn matcher(&self, client_ip_address: IpAddr) -> SubnetMatcher {
        SubnetMatcher::new(self, client_ip_address)
    }

    #[cfg(test)]
    pub fn take_entries(self) -> Vec<(IpNet, SubnetConfiguration)> {
        self.sorted_entries
    }
}

impl DomainNamePattern {
    /// Will append trailing dot where necessary
    pub fn parse(input: &str) -> anyhow::Result<Self> {
        if input == "*" {
            Ok(Self::Any)
        } else if input.starts_with("*.") {
            let without_wildcard = &input[1..];
            Ok(Self::AllSubdomainsOf {
                fqdn_tail: if without_wildcard.ends_with('.') {
                    without_wildcard.to_string()
                } else {
                    format!("{without_wildcard}.")
                },
            })
        } else if input.contains('*') {
            bail!(
                "Wildcards (*) may only appear at the beginning \
                 in place of a subdomain (e.g. '*.example.local')"
            );
        } else {
            Ok(Self::Exact {
                fqdn: if input.ends_with('.') {
                    input.to_string()
                } else {
                    format!("{input}.")
                },
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

impl std::fmt::Display for DomainNamePattern {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Any => write!(f, "*"),
            Self::Exact { fqdn } => write!(f, "{fqdn}"),
            Self::AllSubdomainsOf { fqdn_tail } => write!(f, "*{fqdn_tail}"),
        }
    }
}

impl Rule {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Allow(_) => "allow",
            Self::Block(_) => "block",
        }
    }

    /// Attempt to merge given rule into this rule.
    /// Returns `Err(())` on conflict.
    fn merge(&mut self, other: &Rule) -> Result<(), ()> {
        match (self, other) {
            (Rule::Allow(rule), Rule::Allow(other)) => {
                rule.merge(other);
                Ok(())
            }

            (Rule::Block(rule), Rule::Block(other)) => rule.merge(other),

            (Rule::Allow(_), Rule::Block(_)) | (Rule::Block(_), Rule::Allow(_)) => Err(()),
        }
    }
}

impl AllowRule {
    pub fn for_all_dns_questions() -> Self {
        Self {
            allow_all_dns_questions: true,
            allowed_destination_sockets: Vec::new(),
        }
    }

    pub fn for_destination_socket(addr: SocketAddress) -> Self {
        Self {
            allow_all_dns_questions: false,
            allowed_destination_sockets: vec![addr],
        }
    }

    fn merge(&mut self, other: &AllowRule) {
        self.allow_all_dns_questions |= other.allow_all_dns_questions;
        self.allowed_destination_sockets
            .extend(other.allowed_destination_sockets.iter());
    }
}

impl BlockRule {
    /// Attempt to merge given rule into this rule.
    /// Returns `Err(())` on conflict.
    fn merge(&mut self, other: &Self) -> Result<(), ()> {
        match (self, other) {
            (BlockRule::RefuseDnsQuery, BlockRule::RefuseDnsQuery) => Ok(()),

            (BlockRule::ResolveToStaticIp(ip1), BlockRule::ResolveToStaticIp(ip2))
                if ip1 == ip2 =>
            {
                Ok(())
            }

            _ => Err(()),
        }
    }
}

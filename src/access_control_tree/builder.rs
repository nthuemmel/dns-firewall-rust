use super::*;
use std::cmp::Ordering;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use thiserror::Error;

pub struct AccessControlTreeBuilder {
    entries: BTreeMap<IpNetSortedBySpecificity, SubnetConfigurationBuilder>,
}

#[derive(Debug, Default, PartialEq)]
pub struct SubnetConfigurationBuilder {
    allow_all_dns_queries: bool,
    rules: BTreeMap<DomainNamePatternOrderedBySpecificity, RuleEntry>,
}

/// Most specific subnet (longest prefix) comes first, least specific last
#[derive(Eq, PartialEq, Debug)]
struct IpNetSortedBySpecificity(IpNet);

/// Most specific pattern comes first, least specific last
#[derive(Eq, PartialEq, Debug)]
struct DomainNamePatternOrderedBySpecificity(DomainNamePattern);

#[derive(Debug, PartialEq)]
struct RuleEntry {
    rule: Rule,

    /// Line number of the original rule (for more helpful error messages)
    line_number: usize,
}

#[derive(Debug, Error)]
pub enum AddRuleError {
    #[error("The rule conflicts with another {} rule from line {line_number}", existing_rule.kind())]
    Conflict {
        existing_rule: Rule,
        line_number: usize,
    },
}

impl AccessControlTreeBuilder {
    pub fn new() -> Self {
        Self {
            entries: Default::default(),
        }
    }

    fn entry(&mut self, client_subnet: IpNet) -> &mut SubnetConfigurationBuilder {
        self.entries
            .entry(IpNetSortedBySpecificity(client_subnet))
            .or_default()
    }

    pub fn allow_all_dns_queries(&mut self, client_subnet: IpNet) {
        self.entry(client_subnet).allow_all_dns_queries = true;
    }

    pub fn insert_rule(
        &mut self,
        client_subnet: IpNet,
        domain: DomainNamePattern,
        rule: Rule,
        line_number: usize,
    ) -> Result<(), AddRuleError> {
        match self
            .entry(client_subnet)
            .rules
            .entry(DomainNamePatternOrderedBySpecificity(domain))
        {
            Entry::Vacant(e) => {
                e.insert(RuleEntry { rule, line_number });
                Ok(())
            }
            Entry::Occupied(mut e) => e.get_mut().rule.merge(&rule).map_err(|_| {
                let entry = e.get();
                AddRuleError::Conflict {
                    existing_rule: entry.rule.clone(),
                    line_number: entry.line_number,
                }
            }),
        }
    }

    pub fn build(self) -> AccessControlTree {
        AccessControlTree {
            sorted_entries: self
                .entries
                .into_iter()
                .map(|(subnet, entry)| (subnet.0, entry.build()))
                .collect(),
        }
    }
}

impl SubnetConfigurationBuilder {
    fn build(self) -> SubnetConfiguration {
        SubnetConfiguration {
            allow_all_dns_queries: self.allow_all_dns_queries,
            sorted_rules: self
                .rules
                .into_iter()
                .map(|(domain, entry)| (domain.0, entry.rule))
                .collect(),
        }
    }
}

impl PartialOrd for IpNetSortedBySpecificity {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for IpNetSortedBySpecificity {
    fn cmp(&self, other: &Self) -> Ordering {
        match other.0.prefix_len().cmp(&self.0.prefix_len()) {
            ordering @ (Ordering::Less | Ordering::Greater) => ordering,
            Ordering::Equal => other.0.cmp(&self.0),
        }
    }
}

impl PartialOrd for DomainNamePatternOrderedBySpecificity {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DomainNamePatternOrderedBySpecificity {
    fn cmp(&self, other: &Self) -> Ordering {
        match (&self.0, &other.0) {
            (DomainNamePattern::Any, DomainNamePattern::Any) => Ordering::Equal,
            (DomainNamePattern::Any, _) => Ordering::Greater,
            (_, DomainNamePattern::Any) => Ordering::Less,

            (
                DomainNamePattern::Exact { fqdn: domain1 }
                | DomainNamePattern::AllSubdomainsOf { fqdn_tail: domain1 },
                DomainNamePattern::Exact { fqdn: domain2 }
                | DomainNamePattern::AllSubdomainsOf { fqdn_tail: domain2 },
            ) => match domain2.len().cmp(&domain1.len()) {
                ordering @ (Ordering::Less | Ordering::Greater) => ordering,
                Ordering::Equal => domain2.cmp(domain1),
            },
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn rule_insertion() {
        rule_insertion_impl();
    }

    #[allow(clippy::redundant_clone)]
    pub fn rule_insertion_impl() -> AccessControlTree {
        let mut act1 = AccessControlTreeBuilder::new();

        let ip_1_1_1_1 = IpAddr::from_str("1.1.1.1").unwrap();

        let ipnet_192_168_1_0_24 = IpNet::from_str("192.168.1.0/24").unwrap();
        let ipnet_192_168_2_0_24 = IpNet::from_str("192.168.2.0/24").unwrap();
        let ipnet_192_168_2_0_25 = IpNet::from_str("192.168.2.0/25").unwrap();
        let ipnet_172_10_1_0_24 = IpNet::from_str("172.10.1.0/24").unwrap();

        let domain_test_local = DomainNamePattern::Exact {
            fqdn: "test.local".to_string(),
        };
        let domain_wildcard_test_local = DomainNamePattern::AllSubdomainsOf {
            fqdn_tail: ".test.local".to_string(),
        };
        let domain_a_test_local = DomainNamePattern::Exact {
            fqdn: "a.test.local".to_string(),
        };

        act1.insert_rule(
            ipnet_192_168_1_0_24,
            domain_test_local.clone(),
            Rule::Allow(AllowRule::for_destination_socket(SocketAddress {
                protocol: Protocol::Tcp,
                port: 22,
            })),
            1,
        )
        .unwrap();

        // Merging allow rules should work fine
        act1.insert_rule(
            ipnet_192_168_1_0_24,
            domain_test_local.clone(),
            Rule::Allow(AllowRule::for_destination_socket(SocketAddress {
                protocol: Protocol::Tcp,
                port: 443,
            })),
            1,
        )
        .unwrap();
        act1.insert_rule(
            ipnet_192_168_1_0_24,
            domain_test_local.clone(),
            Rule::Allow(AllowRule::for_all_dns_questions()),
            1,
        )
        .unwrap();

        // Merging allow -> block rules should fail
        assert!(matches!(
            act1.insert_rule(
                ipnet_192_168_1_0_24,
                domain_test_local.clone(),
                Rule::Block(BlockRule::RefuseDnsQuery),
                1,
            ),
            Err(AddRuleError::Conflict { .. })
        ));
        assert!(matches!(
            act1.insert_rule(
                ipnet_192_168_1_0_24,
                domain_test_local.clone(),
                Rule::Block(BlockRule::ResolveToStaticIp(ip_1_1_1_1)),
                1,
            ),
            Err(AddRuleError::Conflict { .. })
        ));

        // Merging block -> allow / other block rules should fail
        act1.insert_rule(
            ipnet_192_168_2_0_24,
            domain_wildcard_test_local.clone(),
            Rule::Block(BlockRule::ResolveToStaticIp(ip_1_1_1_1)),
            1,
        )
        .unwrap();
        assert!(matches!(
            act1.insert_rule(
                ipnet_192_168_2_0_24,
                domain_wildcard_test_local.clone(),
                Rule::Block(BlockRule::RefuseDnsQuery),
                1,
            ),
            Err(AddRuleError::Conflict { .. })
        ));
        assert!(matches!(
            act1.insert_rule(
                ipnet_192_168_2_0_24,
                domain_wildcard_test_local.clone(),
                Rule::Allow(AllowRule::for_destination_socket(SocketAddress {
                    protocol: Protocol::Tcp,
                    port: 443,
                })),
                1,
            ),
            Err(AddRuleError::Conflict { .. })
        ));

        act1.insert_rule(
            ipnet_192_168_2_0_25,
            domain_test_local.clone(),
            Rule::Allow(AllowRule::for_destination_socket(SocketAddress {
                protocol: Protocol::Tcp,
                port: 443,
            })),
            1,
        )
        .unwrap();
        act1.insert_rule(
            ipnet_192_168_2_0_25,
            domain_a_test_local.clone(),
            Rule::Allow(AllowRule::for_destination_socket(SocketAddress {
                protocol: Protocol::Tcp,
                port: 22,
            })),
            1,
        )
        .unwrap();
        act1.insert_rule(
            ipnet_192_168_2_0_25,
            domain_wildcard_test_local.clone(),
            Rule::Block(BlockRule::RefuseDnsQuery),
            1,
        )
        .unwrap();

        act1.insert_rule(
            ipnet_192_168_2_0_24,
            domain_test_local.clone(),
            Rule::Allow(AllowRule::for_destination_socket(SocketAddress {
                protocol: Protocol::Udp,
                port: 514,
            })),
            1,
        )
        .unwrap();

        act1.allow_all_dns_queries(ipnet_172_10_1_0_24);
        act1.insert_rule(
            ipnet_172_10_1_0_24,
            domain_test_local.clone(),
            Rule::Allow(AllowRule::for_destination_socket(SocketAddress {
                protocol: Protocol::Tcp,
                port: 443,
            })),
            1,
        )
        .unwrap();

        let act1 = act1.build();

        assert_eq!(
            act1,
            AccessControlTree {
                sorted_entries: vec![
                    (
                        ipnet_192_168_2_0_25,
                        SubnetConfiguration {
                            allow_all_dns_queries: false,
                            sorted_rules: vec![
                                (
                                    domain_a_test_local.clone(),
                                    Rule::Allow(AllowRule::for_destination_socket(SocketAddress {
                                        protocol: Protocol::Tcp,
                                        port: 22,
                                    }))
                                ),
                                (
                                    domain_wildcard_test_local.clone(),
                                    Rule::Block(BlockRule::RefuseDnsQuery)
                                ),
                                (
                                    domain_test_local.clone(),
                                    Rule::Allow(AllowRule::for_destination_socket(SocketAddress {
                                        protocol: Protocol::Tcp,
                                        port: 443,
                                    }))
                                ),
                            ]
                        }
                    ),
                    (
                        ipnet_192_168_2_0_24,
                        SubnetConfiguration {
                            allow_all_dns_queries: false,
                            sorted_rules: vec![
                                (
                                    domain_wildcard_test_local.clone(),
                                    Rule::Block(BlockRule::ResolveToStaticIp(ip_1_1_1_1))
                                ),
                                (
                                    domain_test_local.clone(),
                                    Rule::Allow(AllowRule::for_destination_socket(SocketAddress {
                                        protocol: Protocol::Udp,
                                        port: 514,
                                    }))
                                ),
                            ]
                        }
                    ),
                    (
                        ipnet_192_168_1_0_24,
                        SubnetConfiguration {
                            allow_all_dns_queries: false,
                            sorted_rules: vec![(
                                domain_test_local.clone(),
                                Rule::Allow(AllowRule {
                                    allow_all_dns_questions: true,
                                    allowed_destination_sockets: vec![
                                        SocketAddress {
                                            protocol: Protocol::Tcp,
                                            port: 22,
                                        },
                                        SocketAddress {
                                            protocol: Protocol::Tcp,
                                            port: 443,
                                        }
                                    ],
                                }),
                            ),]
                        }
                    ),
                    (
                        ipnet_172_10_1_0_24,
                        SubnetConfiguration {
                            allow_all_dns_queries: true,
                            sorted_rules: vec![(
                                domain_test_local.clone(),
                                Rule::Allow(AllowRule {
                                    allow_all_dns_questions: false,
                                    allowed_destination_sockets: vec![SocketAddress {
                                        protocol: Protocol::Tcp,
                                        port: 443,
                                    }],
                                }),
                            ),]
                        }
                    ),
                ]
            }
        );

        act1
    }
}

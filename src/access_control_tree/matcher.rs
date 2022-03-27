use super::*;
use std::net::IpAddr;

#[derive(Clone, Copy)]
pub struct SubnetMatcher<'a> {
    tree: &'a AccessControlTree,
    client_ip_addr: IpAddr,
}

impl<'a> SubnetMatcher<'a> {
    pub(super) fn new(tree: &'a AccessControlTree, client_ip_addr: IpAddr) -> Self {
        Self {
            tree,
            client_ip_addr,
        }
    }

    fn iter(self) -> impl Iterator<Item = &'a SubnetConfiguration> {
        self.tree
            .sorted_entries
            .iter()
            .filter(move |(net, _)| net.contains(&self.client_ip_addr))
            .map(|(_, v)| v)
    }

    pub fn allow_all_dns_queries(self) -> bool {
        self.iter().any(|subnet| subnet.allow_all_dns_queries)
    }

    pub fn find_domain_rule(self, fqdn: &str) -> Rule {
        let sorted_rules = self.iter().flat_map(|subnet| {
            subnet
                .sorted_rules
                .iter()
                .filter(|(domain_name_pattern, _)| domain_name_pattern.matches(fqdn))
                .map(|(_, rule)| rule)
        });

        let mut result = Rule::Block(BlockRule::RefuseDnsQuery);

        for rule in sorted_rules {
            match rule {
                Rule::Allow(rule) => match result {
                    Rule::Block(_) => {
                        // override the initial block rule
                        result = Rule::Allow(rule.clone())
                    }
                    Rule::Allow(ref mut already_allowed) => already_allowed.merge(rule),
                },
                Rule::Block(rule) => {
                    match result {
                        Rule::Block(_) => {
                            // override the initial block rule
                            result = Rule::Block(rule.clone())
                        }
                        Rule::Allow(_) => {
                            // return the aggregated allow rule (which takes precedence).
                            // Evaluation of further rules is cut short here, since they are shadowed by this block rule.
                        }
                    }
                    break;
                }
            }
        }

        result
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn rule_priority() {
        let act = super::builder::tests::rule_insertion_impl();

        let ip_1_1_1_1 = IpAddr::from_str("1.1.1.1").unwrap();
        let ip_192_168_1_24 = IpAddr::from_str("192.168.1.24").unwrap();
        let ip_192_168_2_1 = IpAddr::from_str("192.168.2.1").unwrap();
        let ip_192_168_2_255 = IpAddr::from_str("192.168.2.255").unwrap();

        let matcher_192_168_2_1 = act.matcher(ip_192_168_2_1);
        assert_eq!(
            matcher_192_168_2_1.find_domain_rule("test.local"),
            Rule::Allow(AllowRule {
                allow_all_dns_questions: false,
                allowed_destination_sockets: vec![
                    SocketAddress {
                        protocol: Protocol::Tcp,
                        port: 443,
                    },
                    SocketAddress {
                        protocol: Protocol::Udp,
                        port: 514,
                    }
                ]
            })
        );
        assert_eq!(
            matcher_192_168_2_1.find_domain_rule("b.test.local"),
            Rule::Block(BlockRule::RefuseDnsQuery)
        );
        assert_eq!(
            matcher_192_168_2_1.find_domain_rule("a.test.local"),
            Rule::Allow(AllowRule::for_destination_socket(SocketAddress {
                protocol: Protocol::Tcp,
                port: 22,
            }))
        );
        assert_eq!(
            matcher_192_168_2_1.find_domain_rule("other"),
            Rule::Block(BlockRule::RefuseDnsQuery)
        );

        let matcher_192_168_2_255 = act.matcher(ip_192_168_2_255);
        assert_eq!(
            matcher_192_168_2_255.find_domain_rule("test.local"),
            Rule::Allow(AllowRule {
                allow_all_dns_questions: false,
                allowed_destination_sockets: vec![SocketAddress {
                    protocol: Protocol::Udp,
                    port: 514,
                }]
            })
        );
        assert_eq!(
            matcher_192_168_2_255.find_domain_rule("b.test.local"),
            Rule::Block(BlockRule::ResolveToStaticIp(ip_1_1_1_1))
        );
        assert_eq!(
            matcher_192_168_2_255.find_domain_rule("a.test.local"),
            Rule::Block(BlockRule::ResolveToStaticIp(ip_1_1_1_1))
        );
        assert_eq!(
            matcher_192_168_2_255.find_domain_rule("other"),
            Rule::Block(BlockRule::RefuseDnsQuery)
        );

        let matcher_192_168_1_24 = act.matcher(ip_192_168_1_24);
        assert_eq!(
            matcher_192_168_1_24.find_domain_rule("test.local"),
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
                ]
            })
        );
        assert_eq!(
            matcher_192_168_1_24.find_domain_rule("b.test.local"),
            Rule::Block(BlockRule::RefuseDnsQuery)
        );
        assert_eq!(
            matcher_192_168_1_24.find_domain_rule("a.test.local"),
            Rule::Block(BlockRule::RefuseDnsQuery)
        );
        assert_eq!(
            matcher_192_168_1_24.find_domain_rule("other"),
            Rule::Block(BlockRule::RefuseDnsQuery)
        );

        let matcher_1_1_1_1 = act.matcher(ip_1_1_1_1);
        assert_eq!(
            matcher_1_1_1_1.find_domain_rule("test.local"),
            Rule::Block(BlockRule::RefuseDnsQuery)
        );
        assert_eq!(
            matcher_1_1_1_1.find_domain_rule("b.test.local"),
            Rule::Block(BlockRule::RefuseDnsQuery)
        );
        assert_eq!(
            matcher_1_1_1_1.find_domain_rule("a.test.local"),
            Rule::Block(BlockRule::RefuseDnsQuery)
        );
        assert_eq!(
            matcher_1_1_1_1.find_domain_rule("other"),
            Rule::Block(BlockRule::RefuseDnsQuery)
        );
    }
}

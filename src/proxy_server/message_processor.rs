use crate::access_control_tree::{ACTSocketAddress, AccessControlTree};
use crate::firewall_backend::FirewallBackend;
use crate::proxy_server::access_logger::{AccessLogger, LogEntryKind};
use dns_parser::{Class, Opcode, QueryClass, QueryType, RData, ResponseCode};
use rand::Rng;
use std::net::IpAddr;

pub struct DnsMessageProcessor {
    act: AccessControlTree,
    pub access_logger: AccessLogger,
    min_ttl: chrono::Duration,
    max_ttl: chrono::Duration,
    firewall_backend: Box<dyn FirewallBackend>,
}

pub enum RequestReaction {
    Discard,
    ForwardToUpstream { forwarded_request: ForwardedRequest },
    RespondToClient,
}

pub struct ForwardedRequest {
    pub original_request_header: dns_parser::Header,

    request_id: u16,

    // Mapping of [domain name] -> [list of socket addr]. Used to create firewall rules.
    // Vec instead of HashMap because we expect a single domain name for most requests.
    // A map would waste memory.
    allowed_domains: Vec<AllowedDomain>,
}

#[derive(Clone)]
struct AllowedDomain {
    domain_name: String,
    socket_addrs: Vec<ACTSocketAddress>,
}

pub enum ResponseReaction {
    /// Discard & receive another response from the server
    Discard,
    ForwardToClient,
}

impl DnsMessageProcessor {
    pub fn new(
        act: AccessControlTree,
        min_ttl: chrono::Duration,
        max_ttl: chrono::Duration,
        firewall_backend: Box<dyn FirewallBackend>,
    ) -> Self {
        Self {
            act,
            access_logger: AccessLogger {},
            min_ttl,
            max_ttl,
            firewall_backend,
        }
    }

    pub fn process_client_request(
        &self,
        client_address: IpAddr,
        buffer: &mut Vec<u8>,
    ) -> RequestReaction {
        // Parse request
        let request = match dns_parser::Packet::parse(buffer) {
            Ok(packet) => packet,
            Err(e) => {
                self.access_logger.log(
                    client_address,
                    LogEntryKind::RequestError,
                    None,
                    &format!("Request decoding failed: {}", e),
                );
                return RequestReaction::Discard;
            }
        };

        let act_entries = self.act.get_matching_entries(client_address);
        // We still continue even if actEntries is empty (sender not allowed), to generate log messages
        let always_allow_dns_query = act_entries.iter().any(|e| e.allow_all_dns_queries);

        // Validate for QUERY OPCODE, unless all DNS queries are allowed
        if !always_allow_dns_query {
            if request.header.opcode != Opcode::StandardQuery {
                self.access_logger.log(
                    client_address,
                    LogEntryKind::RequestWarning,
                    Some(request.header.id),
                    &format!(
                        "Unexpected OPCODE {:?} (expected StandardQuery)",
                        request.header.opcode
                    ),
                );
                Self::build_response(&request.header, ResponseCode::Refused, buffer);
                return RequestReaction::RespondToClient;
            }

            if request.header.questions == 0 {
                self.access_logger.log(
                    client_address,
                    LogEntryKind::RequestWarning,
                    Some(request.header.id),
                    "Empty request",
                );
                Self::build_response(&request.header, ResponseCode::Refused, buffer);
                return RequestReaction::RespondToClient;
            }
        }

        // Gather requested domain names
        let mut allowed_domains = Vec::with_capacity(request.header.questions as usize);
        let mut blocked_at_least_one_domain = false;

        for question in &request.questions {
            let qname = question.qname.to_string();
            let mut always_allow_dns_question = always_allow_dns_query;
            let mut allowed_destination_sockets = Vec::new();

            for act_entry in &act_entries {
                if let Some(entry) = act_entry.domain_name_map.get(&qname) {
                    always_allow_dns_question |= entry.allow_all_dns_questions;
                    allowed_destination_sockets.extend(entry.allowed_destination_sockets.iter());
                }
            }

            if question.qclass != QueryClass::IN {
                if always_allow_dns_question {
                    continue;
                } else {
                    self.access_logger.log(
                        client_address,
                        LogEntryKind::RequestWarning,
                        Some(request.header.id),
                        &format!(
                            "{}: Unexpected QCLASS {:?} (expected IN)",
                            qname, question.qclass,
                        ),
                    );
                    Self::build_response(&request.header, ResponseCode::Refused, buffer);
                    return RequestReaction::RespondToClient;
                }
            }

            if question.qtype != QueryType::A && question.qtype != QueryType::AAAA {
                if always_allow_dns_question {
                    continue;
                } else {
                    self.access_logger.log(
                        client_address,
                        LogEntryKind::RequestWarning,
                        Some(request.header.id),
                        &format!(
                            "{}: Unexpected QTYPE {:?} (expected A or AAAA)",
                            qname, question.qtype,
                        ),
                    );
                    Self::build_response(&request.header, ResponseCode::Refused, buffer);
                    return RequestReaction::RespondToClient;
                }
            }

            if always_allow_dns_question || !allowed_destination_sockets.is_empty() {
                allowed_domains.push(AllowedDomain {
                    domain_name: qname,
                    socket_addrs: allowed_destination_sockets.into_iter().cloned().collect(),
                });
            } else {
                // Access to the domain's IP addresses will remain blocked in the firewall, and the DNS query will be blocked
                self.access_logger.log(
                    client_address,
                    LogEntryKind::RequestBlocked,
                    Some(request.header.id),
                    &qname,
                );
                blocked_at_least_one_domain = true;
            }
        }

        if blocked_at_least_one_domain {
            Self::build_response(&request.header, ResponseCode::Refused, buffer);
            return RequestReaction::RespondToClient;
        }

        if allowed_domains.is_empty() {
            // No destination sockets will be allowed in the firewall, but the DNS request itself will be allowed
            self.access_logger.log(
                client_address,
                LogEntryKind::RequestOnlyAllowed,
                Some(request.header.id),
                "",
            );
        } else {
            for allowed_domain in &allowed_domains {
                if allowed_domain.socket_addrs.is_empty() {
                    // Access to the domain's IP addresses will remain blocked in the firewall
                    self.access_logger.log(
                        client_address,
                        LogEntryKind::RequestOnlyAllowed,
                        Some(request.header.id),
                        &allowed_domain.domain_name,
                    );
                } else {
                    self.access_logger.log(
                        client_address,
                        LogEntryKind::RequestAndNetworkAllowed,
                        Some(request.header.id),
                        &allowed_domain.domain_name,
                    );
                }
            }
        }

        // Replace request ID by a randomly generated one (to prevent potential ID clashes on malicious client input)
        let forwarded_request_id: u16 = rand::thread_rng().gen();

        let request_header = request.header;

        // The DNS library may not support some parts of the request (and could omit them when re-encoding).
        // Therefore, we replace the ID of the request directly in the buffer.
        // This ensures that the whole request is being forwarded.
        buffer[..2].copy_from_slice(&forwarded_request_id.to_be_bytes());

        RequestReaction::ForwardToUpstream {
            forwarded_request: ForwardedRequest {
                original_request_header: request_header,
                request_id: forwarded_request_id,
                allowed_domains,
            },
        }
    }

    pub async fn process_upstream_response(
        &self,
        client_address: IpAddr,
        buffer: &mut Vec<u8>,
        forwarded_request: &ForwardedRequest,
    ) -> ResponseReaction {
        // Parse response
        let response = match dns_parser::Packet::parse(buffer) {
            Ok(packet) => packet,
            Err(e) => {
                self.access_logger.log(
                    client_address,
                    LogEntryKind::ResponseError,
                    Some(forwarded_request.request_id),
                    &format!("Response decoding failed: {}", e),
                );
                return ResponseReaction::Discard;
            }
        };

        // Process response
        if response.header.id != forwarded_request.request_id {
            // Unrelated response, ignore
            self.access_logger.log(
                client_address,
                LogEntryKind::ResponseError,
                Some(forwarded_request.request_id),
                &format!(
                    "Received unrelated request ID (expected {}, got {})",
                    forwarded_request.request_id, response.header.id
                ),
            );
            return ResponseReaction::Discard;
        }

        if response.header.opcode != Opcode::StandardQuery
            || response.header.response_code != ResponseCode::NoError
        {
            self.access_logger.log(
                client_address,
                LogEntryKind::ResponseError,
                Some(forwarded_request.original_request_header.id),
                &format!(
                    "Upstream returned error (OPCODE {:?}, RCODE {:?})",
                    response.header.opcode, response.header.response_code
                ),
            );
            // Response does not contain expected answer, we don't further parse it, but forward it
            // to the client
            return forward(buffer, forwarded_request);
        }

        // We assume the upstream DNS server is trustworthy and do not cross-check the questions
        // section against the original request.

        let mut firewall_reconfigured = false;

        for answer in &response.answers {
            if answer.cls != Class::IN {
                continue;
            }

            let ip_address = match &answer.data {
                RData::A(record) => {
                    if !client_address.is_loopback() && !client_address.is_ipv4() {
                        // Ignore resolved address when client is not localhost and uses other IP family.
                        // Both client and destination must use the same IP family in order to insert firewall rules,
                        // unless client == localhost, in which case IP-family independent rules can be added.
                        continue;
                    }
                    IpAddr::V4(record.0)
                }
                RData::AAAA(record) => {
                    if !client_address.is_loopback() && !client_address.is_ipv6() {
                        // See RData::A above
                        continue;
                    }
                    IpAddr::V6(record.0)
                }
                _ => continue,
            };

            for allowed_domain in forwarded_request
                .find_allowed_domains_with_cnames(&response, answer.name.to_string())
            {
                let ttl = chrono::Duration::seconds(answer.ttl as i64);
                let ttl = if ttl < self.min_ttl {
                    self.min_ttl
                } else if ttl > self.max_ttl {
                    self.max_ttl
                } else {
                    ttl
                };

                for socket_addr in allowed_domain.socket_addrs {
                    self.access_logger.log(
                        client_address,
                        LogEntryKind::ResponseForwardedAndFirewallRuleAdded,
                        Some(forwarded_request.original_request_header.id),
                        &format!(
                            "{} [{}]:{}:{} TTL:{}",
                            allowed_domain.domain_name,
                            ip_address,
                            socket_addr.protocol,
                            socket_addr.port,
                            ttl.num_seconds()
                        ),
                    );

                    self.firewall_backend
                        .add_temporary_allow_rule(
                            client_address,
                            ip_address,
                            socket_addr,
                            ttl,
                            &allowed_domain.domain_name,
                        )
                        .await;

                    firewall_reconfigured = true;
                }
            }
        }

        if !firewall_reconfigured {
            // Make sure to log at least something, to indicate that the response went through
            self.access_logger.log(
                client_address,
                LogEntryKind::ResponseOnlyForwarded,
                Some(forwarded_request.original_request_header.id),
                "",
            );
        }

        forward(buffer, forwarded_request)
    }

    pub fn build_response(
        request_header: &dns_parser::Header,
        rcode: ResponseCode,
        buffer: &mut Vec<u8>,
    ) {
        // Build response
        let response_header = dns_parser::Header {
            id: request_header.id,
            query: false,
            opcode: request_header.opcode,
            authoritative: false,
            truncated: false,
            recursion_desired: request_header.recursion_desired,
            recursion_available: true,
            authenticated_data: false,
            checking_disabled: false,
            response_code: rcode,
            questions: 0,
            answers: 0,
            nameservers: 0,
            additional: 0,
        };

        // Encode response
        buffer.resize(12, 0);
        response_header.write(&mut buffer[..12]);
    }
}

fn forward(buffer: &mut Vec<u8>, forwarded_request: &ForwardedRequest) -> ResponseReaction {
    // Replace generated ID with original ID
    buffer[..2].copy_from_slice(&forwarded_request.original_request_header.id.to_be_bytes());
    ResponseReaction::ForwardToClient
}

impl ForwardedRequest {
    /// Find all mappings of the form [allowed domain name] -> [list of socket addr]
    /// for the given `domain_name`. This considers CNAME indirections in the given `response` too.
    fn find_allowed_domains_with_cnames(
        &self,
        response: &dns_parser::Packet,
        domain_name: String,
    ) -> Vec<AllowedDomain> {
        let mut result = Vec::new();

        // We iterate over the list of names while appending resolved CNAMEs at the same time.
        // CNAMEs will only be added if they were not already traversed before, preventing any loops.
        let mut name_list = vec![domain_name];

        let mut i = 0;
        while i < name_list.len() {
            let name = name_list[i].clone();

            // Try to find domain name directly
            result.extend(
                self.allowed_domains
                    .iter()
                    .filter(|v| v.domain_name == name)
                    .cloned(),
            );

            // Try to find CNAMEs pointing to it
            for answer in &response.answers {
                if answer.cls == Class::IN {
                    if let RData::CNAME(cname) = &answer.data {
                        let cname = cname.0.to_string();
                        if cname == name {
                            let cname_source_domain_name = answer.name.to_string();
                            // Only consider this CNAME's source domain if we didn't process it
                            // previously
                            if !name_list.contains(&cname_source_domain_name) {
                                name_list.push(cname_source_domain_name);
                            }
                        }
                    }
                }
            }

            i += 1;
        }

        result
    }
}

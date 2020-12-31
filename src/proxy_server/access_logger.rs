use std::net::IpAddr;

pub struct AccessLogger {}

pub enum LogEntryKind {
    RequestError,
    RequestWarning,
    RequestBlocked,
    RequestOnlyAllowed,
    RequestAndNetworkAllowed,
    ResponseError,
    ResponseOnlyForwarded,
    ResponseForwardedAndFirewallRuleAdded,
}

impl AccessLogger {
    pub fn log(
        &self,
        client_address: IpAddr,
        kind: LogEntryKind,
        request_id: Option<u16>,
        message: &str,
    ) {
        let arrow = match kind {
            LogEntryKind::RequestError => "!>",
            LogEntryKind::RequestWarning => "!>",
            LogEntryKind::RequestBlocked => "|>",
            LogEntryKind::RequestOnlyAllowed => "~>",
            LogEntryKind::RequestAndNetworkAllowed => "->",
            LogEntryKind::ResponseError => "<!",
            LogEntryKind::ResponseOnlyForwarded => "<~",
            LogEntryKind::ResponseForwardedAndFirewallRuleAdded => "<-",
        };

        if let Some(id) = request_id {
            println!("{} {} [{}] {}", client_address, arrow, id, message);
        } else {
            println!("{} {} {}", client_address, arrow, message);
        }
    }
}

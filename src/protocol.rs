#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub fn parse(input: &str) -> Option<Protocol> {
        if input.eq_ignore_ascii_case("TCP") {
            Some(Protocol::Tcp)
        } else if input.eq_ignore_ascii_case("UDP") {
            Some(Protocol::Udp)
        } else {
            None
        }
    }

    /// Returns the protocol number as per https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
    /// (usually stored in /etc/protocols)
    pub fn number(self) -> u32 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
        }
    }
}

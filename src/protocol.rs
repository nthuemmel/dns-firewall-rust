#[derive(Debug, Clone, Copy)]
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
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
        }
    }
}

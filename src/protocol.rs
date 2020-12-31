#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    TCP,
    UDP,
}

impl Protocol {
    pub fn parse(input: &str) -> Option<Protocol> {
        if input.eq_ignore_ascii_case("TCP") {
            Some(Protocol::TCP)
        } else if input.eq_ignore_ascii_case("UDP") {
            Some(Protocol::UDP)
        } else {
            None
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::TCP => write!(f, "TCP"),
            Self::UDP => write!(f, "UDP"),
        }
    }
}

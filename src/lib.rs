use std::error::Error;
use std::fmt;
use std::net::IpAddr;

struct InvalidArgs;
struct NotSudo;

#[derive(Clone, Debug)]
pub enum SetupError {
    InvalidArgs,
    NoArgs,
    NotSudo,
}

impl Error for SetupError {}

impl fmt::Display for SetupError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidArgs => write!(f, "The provided arguments are invalid. Please run `sudo imd ip_address_1 [hostname_1] [ip_address_2 [hostname_2]]..."),
            Self::NoArgs => write!(f, "imd needs at least one target. Please run sudo imd ip_address_1 [hostname_1] [ip_address_2 [hostname_2]]..."),
            Self::NotSudo => write!(f, "imd must be run with root permissions. Please try running 'sudo !!'"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TargetMachine {
    ip_address: IpAddr,
    hostname: Option<String>
}

impl TargetMachine {
    pub fn new(ip_address: IpAddr, hostname: Option<String>) -> TargetMachine {
        TargetMachine {
            ip_address,
            hostname,
        }
    }
}
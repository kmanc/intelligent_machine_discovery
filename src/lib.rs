use nix::unistd::{chown, Gid, Uid};
use std::error::Error;
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

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
    hostname: Option<String>, 
    ip_address: IpAddr,
}

impl TargetMachine {
    pub fn hostname(&self) -> &Option<String> {
        &self.hostname
    }

    pub fn ip_address(&self) -> &IpAddr {
        &self.ip_address
    }

    pub fn new(hostname: Option<String>, ip_address: IpAddr) -> TargetMachine {
        TargetMachine {
            ip_address,
            hostname,
        }
    }
}

#[derive(Clone, Debug)]
pub struct IMDUser {
    gid: Gid,
    name: String,
    uid: Uid,
}

impl IMDUser {
    pub fn gid(&self) -> &Gid {
        &self.gid
    }

    pub fn name(&self) -> &String {
        &self.name
    }

    pub fn new(gid: Gid, name: String, uid: Uid) -> IMDUser {
        IMDUser {
            gid,
            name,
            uid,
        }
    }

    pub fn uid(&self) -> &Uid {
        &self.uid
    }

}

pub fn change_owner(object: &str, new_owner: Arc<IMDUser>) -> Result<(), Box<dyn Error>> {
    chown(object, Some(*new_owner.uid()), Some(*new_owner.gid()))?;
    Ok(())
}

pub fn format_log(machine: &str, log: &str) -> String {
    format!("{machine: <16}- {log}").to_string()
}
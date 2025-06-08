use crossterm::style::{StyledContent, Stylize};
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum PanicDiscoveryError {
    InvalidIPAddress,
    InvalidWordlist,
    NotRunAsRoot,
}

impl PanicDiscoveryError {
    pub fn as_str(&self) -> StyledContent<&str> {
        match self {
            PanicDiscoveryError::InvalidIPAddress => {
                "The provided value does not contain a valid IP address".red()
            }
            PanicDiscoveryError::InvalidWordlist => "The provided value is not a valid file".red(),
            PanicDiscoveryError::NotRunAsRoot => {
                "✕ imd must be run as root. Try `sudo !!` to retry that command with sudo".red()
            }
        }
    }
}

impl fmt::Display for PanicDiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Error for PanicDiscoveryError {}

#[derive(Debug)]
pub enum RecoverableDiscoveryError {
    AlreadyInHost,
    Connection,
    DirectoryExists,
    Services,
}

impl RecoverableDiscoveryError {
    pub fn as_str(&self) -> StyledContent<&str> {
        match self {
            RecoverableDiscoveryError::AlreadyInHost => "〰 Entry already in '/etc/hosts'".yellow(),
            RecoverableDiscoveryError::Connection => {
                "✕ Could not ping host, it might be down".red()
            }
            RecoverableDiscoveryError::DirectoryExists => "〰 Directory already exists".yellow(),
            RecoverableDiscoveryError::Services => {
                "✕ Could not discover host services, ending discovery".red()
            }
        }
    }
}

impl fmt::Display for RecoverableDiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Error for RecoverableDiscoveryError {}

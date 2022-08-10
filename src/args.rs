use nix::unistd::{Gid, Uid, User};
use std::env;
use std::error::Error;
use std::fmt;
use std::net::IpAddr;
use std::process::Command;
use std::sync::Arc;

#[derive(Debug)]
pub struct Args {
    machines: Vec<Arc<imd::TargetMachine>>,
    real_user: Arc<imd::IMDUser>,
}

impl Args {
    pub fn machines(&self) -> &Vec<Arc<imd::TargetMachine>> {
        &self.machines
    }

    pub fn parse() -> Result<Args, ArgsError> {
        // Set an empty vec for referenced counted target machines
        let mut machines: Vec<Arc<imd::TargetMachine>> = vec![];
        // Set an initial value of None for a look-back on parsing the arguments
        let mut last: Option<IpAddr> = None;
        // Grab user-entered arguments, skip the first (which will be imd), and trim the rest
        let user_entered = env::args().skip(1)
                                      .map(|s| s.trim().to_string());
        for value in user_entered {
            // Try to parse the entered value as an IP address
            match value.parse::<IpAddr>() {
                // If it's a valid IP address, check last to see if it is currently set
                Ok(ip) => {
                    last = match last {
                        // If last is None, set last to the IP address just parsed
                        None => Some(ip),
                        // If last is an IP address, the user entered two IP addresses in a row, so we should push last to the vec
                        _ => {
                            machines.push(
                                Arc::new(
                                    imd::TargetMachine::new(
                                        None, 
                                        last.unwrap(),
                            )));
                            Some(ip)
                        }
                    };
                },
                // If the parse returns an error, it is likely a hostname
                Err(_) => {
                    last = match last {
                        // If last is None, that means they entered two non IP addresses in a row, which is not supported
                        None => return Err(ArgsError::InvalidArgs),
                        // If last was something, they entered the hostname to a previously entered IP address, so we should push it
                        _ => {
                            machines.push(
                                Arc::new(
                                    imd::TargetMachine::new(
                                        Some(value.to_owned()),
                                        last.unwrap(),
                            )));
                            None
                        }
                    };
                }
            };
        }

        // If last is not None at the end of the loop, we need to push the last arg because it was an IP address
        if last != None {
            machines.push(
                Arc::new(
                    imd::TargetMachine::new(
                        None,
                        last.unwrap(),
            )))
        }

        // imd needs something to target - ensure that's the case here
        if machines.is_empty() {
            return Err(ArgsError::NoArgs);
        }

        // imd must be run as root to work - ensure that's the case here
        if !Uid::effective().is_root() {
            return Err(ArgsError::NotSudo);
        }

        // Run the who command to determine the logged in user (hopefully the person who ran imd)
        let name = String::from_utf8(Command::new("who").output().unwrap().stdout).unwrap();
        // Parse out the important part
        let name = String::from(name.split(' ').collect::<Vec<&str>>()[0]);

        // Get the user ID from the username
        let (uid, gid) = match User::from_name(&name).unwrap() {
            Some(user) => (user.uid, user.gid),
            _ => (Uid::from_raw(0), Gid::from_raw(0))
        };

        let user = imd::IMDUser::new(
            gid,
            name,
            uid
        );

        // Return the args, which includes the target machines and thelogged in user
        Ok(Args {
            machines,
            real_user: Arc::new(user),
        })
    }

    pub fn real_user(&self) -> &Arc<imd::IMDUser> {
        &self.real_user
    }

}

#[derive(Clone, Debug)]
pub enum ArgsError {
    InvalidArgs,
    NoArgs,
    NotSudo,
}

impl Error for ArgsError {}

impl fmt::Display for ArgsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidArgs => write!(f, "The provided arguments are invalid. Please run `sudo imd ip_address_1 [hostname_1] [ip_address_2 [hostname_2]]..."),
            Self::NoArgs => write!(f, "imd needs at least one target. Please run sudo imd ip_address_1 [hostname_1] [ip_address_2 [hostname_2]]..."),
            Self::NotSudo => write!(f, "imd must be run with root permissions. Please try running 'sudo !!'"),
        }
    }
}

use nix::unistd::Uid;
use std::env;
use std::error::Error;
use std::net::IpAddr;
use std::process::Command;
use std::sync::Arc;

#[derive(Debug)]
pub struct Args {
    machines: Vec<Arc<imd::TargetMachine>>,
    real_user: Arc<String>,
}

impl Args {
    pub fn parse() -> Result<Args, imd::SetupError> {
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
                                        last.unwrap(),
                                        None
                            )));
                            Some(ip)
                        }
                    };
                },
                // If the parse returns an error, it is likely a hostname
                Err(_) => {
                    last = match last {
                        // If last is None, that means they entered two non IP addresses in a row, which is not supported
                        None => return Err(imd::SetupError::InvalidArgs),
                        // If last was something, they entered the hostname to a previously entered IP address, so we should push it
                        _ => {
                            machines.push(
                                Arc::new(
                                    imd::TargetMachine::new(
                                        last.unwrap(),
                                        Some(value.to_owned()),
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
                        last.unwrap(),
                        None,
            )))
        }

        // imd needs something to target - ensure that's the case here
        if machines.is_empty() {
            return Err(imd::SetupError::NoArgs);
        }

        // imd must be run as root to work - ensure that's the case here
        if !Uid::effective().is_root() {
            return Err(imd::SetupError::NotSudo);
        }

        // Run the who command to determine the user who ran the program (through sudo)
        let who = String::from_utf8(Command::new("who").output().unwrap().stdout).unwrap();
        // Parse out the important part
        let who = String::from(who.split(' ').collect::<Vec<&str>>()[0]);

        // Return the args, which includes the target machines and thelogged in user
        Ok(Args {
            machines: machines,
            real_user: Arc::new(who),
        })
    }
}

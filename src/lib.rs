use crossterm::style::Stylize;
use nix::unistd::{chown, Gid, Uid};
use std::error::Error;
use std::fs::File;
use std::net::IpAddr;
use std::process::Command;
use std::sync::Arc;


pub enum Color {
    Green,
    Red,
}


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
            hostname,
            ip_address,
        }
    }
}


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


pub fn create_file(user: Arc<IMDUser>, filename: &str) -> Result<File, Box<dyn Error>> {
    // Create the desired file
    let f = File::create(filename)?;

    // Change ownership of the file to the logged in user from Args
    change_owner(filename, user)?;

    Ok(f)
}


pub fn format_log(machine: &str, log: &str, color: Option<Color>) -> String {
    match color {
        Some(Color::Green) => format!("{machine: <16}- {log}").green().to_string(),
        None => format!("{machine: <16}- {log}"),
        Some(Color::Red) => format!("{machine: <16}- {log}").red().to_string(),
    }
}


pub fn get_command_output(command: &str, args: Vec<&str>) -> Result<String, Box<dyn Error>> {
    let out = Command::new(command)
        .args(args)
        .output()?;
    let out = String::from_utf8(out.stdout)?;

    Ok(out)
}

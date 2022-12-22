use crossterm::style::{StyledContent, Stylize};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use nix::unistd::{chown, Gid, Uid};
use std::error::Error;
use std::fs::File;
use std::net::IpAddr;
use std::process::Command;

enum Color {
    Green,
    Red,
    Yellow,
}

pub enum IMDOutcome {
    Bad,
    Good,
    Neutral,
}

pub enum PingResult {
    Good,
    Bad,
}

#[derive(Clone)]
pub struct TargetMachine {
    hostname: Option<String>,
    ip_address: IpAddr,
    web_target: String,
}

impl TargetMachine {
    pub fn hostname(&self) -> &Option<String> {
        &self.hostname
    }

    pub fn ip_address(&self) -> &IpAddr {
        &self.ip_address
    }

    pub fn new(hostname: Option<String>, ip_address: IpAddr, web_target: String) -> TargetMachine {
        TargetMachine {
            hostname,
            ip_address,
            web_target,
        }
    }

    pub fn web_target(&self) -> &String {
        &self.web_target
    }
}

#[derive(Clone)]
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
        IMDUser { gid, name, uid }
    }

    pub fn uid(&self) -> &Uid {
        &self.uid
    }
}

pub struct DiscoveryArgs {
    bars_container: MultiProgress,
    machine: TargetMachine,
    user: IMDUser,
    wordlist: String,
}

impl DiscoveryArgs {
    pub fn bars_container(&self) -> &MultiProgress {
        &self.bars_container
    }

    pub fn machine(&self) -> &TargetMachine {
        &self.machine
    }

    pub fn new(
        bars_container: MultiProgress,
        machine: TargetMachine,
        user: IMDUser,
        wordlist: String,
    ) -> DiscoveryArgs {
        DiscoveryArgs {
            bars_container,
            machine,
            user,
            wordlist,
        }
    }

    pub fn user(&self) -> &IMDUser {
        &self.user
    }

    pub fn wordlist(&self) -> &String {
        &self.wordlist
    }
}

pub fn change_owner(object: &str, new_owner: &IMDUser) -> Result<(), Box<dyn Error>> {
    chown(object, Some(*new_owner.uid()), Some(*new_owner.gid()))?;
    Ok(())
}

pub fn create_file(user: &IMDUser, filename: &str) -> Result<File, Box<dyn Error>> {
    // Create the desired file
    let f = File::create(filename)?;

    // Change ownership of the file to the logged in user from Args
    change_owner(filename, user)?;

    Ok(f)
}

fn color_text(text: &str, color: Color) -> StyledContent<&str> {
    match color {
        Color::Green => text.green(),
        Color::Red => text.red(),
        Color::Yellow => text.yellow(),
    }
}

fn format_ip_address(ip_address: &str) -> String {
    format!("{ip_address: <16}- ")
}

pub fn get_command_output(command: &str, args: Vec<&str>) -> Result<String, Box<dyn Error>> {
    let out = Command::new(command).args(args).output()?;
    let out = String::from_utf8(out.stdout)?;

    Ok(out)
}

pub fn make_new_bar() -> ProgressBar {
    let style = ProgressStyle::with_template("{msg}").unwrap();
    ProgressBar::new(0).with_style(style)
}

pub fn make_message_starter(ip_address: &str, content: &str) -> String {
    let formatted_ip = format_ip_address(ip_address);
    format!("{formatted_ip}{content} ")
}

pub fn report(outcome: &IMDOutcome, text: &str) -> String {
    let (text, color) = match outcome {
        IMDOutcome::Bad => (format!("✕ {text}"), Color::Red),
        IMDOutcome::Good => (format!("✔️ {text}"), Color::Green),
        IMDOutcome::Neutral => (format!("~ {text}"), Color::Yellow),
    };
    color_text(&text, color).to_string()
}

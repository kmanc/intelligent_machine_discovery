use crossterm::style::{StyledContent, Stylize};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use nix::unistd::{self, Gid, Uid};
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::process::Command;
use std::sync::Arc;

pub enum IMDOutcome {
    Bad,
    Good,
    Neutral,
}

#[derive(Clone)]
pub struct TargetMachine {
    hostname: Option<String>,
    ip_address: String,
    mp: Arc<MultiProgress>,
    print_pad: usize,
}

impl TargetMachine {
    pub fn new(
        hostname: Option<String>,
        ip_address: String,
        mp: Arc<MultiProgress>,
        print_pad: usize,
    ) -> TargetMachine {
        TargetMachine {
            hostname,
            ip_address,
            mp,
            print_pad,
        }
    }

    pub fn add_new_bar(&self) -> ProgressBar {
        let bar = self.mp.add(ProgressBar::new(0));
        let style = ProgressStyle::with_template("{msg}").unwrap();
        bar.set_style(style);
        bar
    }

    pub fn discovery(&self) {
    }

    pub fn format_command_start(&self, text: &str) -> String {
        format!(
            "{ip_address: <pad_length$}- {text}",
            ip_address = self.ip_address,
            pad_length = self.print_pad,
        )
    }

    pub fn hostname(&self) -> &Option<String> {
        &self.hostname
    }

    pub fn ip_address(&self) -> &str {
        &self.ip_address
    }

    pub fn web_target(&self) -> String {
        match &self.hostname {
            Some(hostname) => hostname.to_string(),
            None => self.ip_address().to_string(),
        }
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
    pub fn add_new_bar(&self) -> ProgressBar {
        let bar = self.bars_container.add(ProgressBar::new(0));
        let style = ProgressStyle::with_template("{msg}").unwrap();
        bar.set_style(style);
        bar
    }

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
    unistd::chown(object, Some(*new_owner.uid()), Some(*new_owner.gid()))?;
    Ok(())
}

pub fn create_file(
    user: &IMDUser,
    filename: &str,
    _command: &str,
    bar: &ProgressBar,
    starter: &str,
) -> Result<File, Box<dyn Error>> {
    // Create the desired file
    let f = match File::create(filename) {
        Err(err) => {
            let message = format_command_result(
                &IMDOutcome::Bad,
                "Problem creating file for the output of the {_command} command",
            );
            bar.finish_with_message(format!("{starter}{message}"));
            return Err(Box::new(err));
        }
        Ok(f) => f,
    };

    // Change ownership of the file to the logged in user from Args
    change_owner(filename, user)?;

    Ok(f)
}

pub fn get_command_output(
    command: &str,
    args: Vec<&str>,
    bar: &ProgressBar,
    starter: &str,
) -> Result<String, Box<dyn Error>> {
    let out = match Command::new(command).args(args).output() {
        Err(err) => {
            let message = format!("Problem running {command} command");
            let message = format_command_result(&IMDOutcome::Bad, &message);
            bar.finish_with_message(format!("{starter}{message}"));
            return Err(Box::new(err));
        }
        Ok(out) => out,
    };
    let out = match String::from_utf8(out.stdout) {
        Err(err) => {
            let message = format!("Problem parsing {command} output");
            let message = format_command_result(&IMDOutcome::Bad, &message);
            bar.finish_with_message(format!("{starter}{message}"));
            return Err(Box::new(err));
        }
        Ok(out) => out,
    };

    Ok(out)
}

pub fn add_new_bar(bars_container: &MultiProgress) -> ProgressBar {
    let bar = bars_container.add(ProgressBar::new(0));
    let style = ProgressStyle::with_template("{msg}").unwrap();
    bar.set_style(style);
    bar
}

// NOTE: this will possibly move to be within a TargetMachine or other struct
pub fn format_command_start(ip_address: &str, pad_length: usize, text: &str) -> String {
    format!(
        "{ip_address: <pad_length$}- {text}",
        pad_length = pad_length,
    )
}

// NOTE: this will possibly move to be within a TargetMachine or other struct
pub fn format_command_result(outcome: &IMDOutcome, text: &str) -> StyledContent<String> {
    match outcome {
        IMDOutcome::Bad => format!("✕ {text}").red(),
        IMDOutcome::Good => format!("✔️ {text}").green(),
        IMDOutcome::Neutral => format!("~ {text}").yellow(),
    }
}

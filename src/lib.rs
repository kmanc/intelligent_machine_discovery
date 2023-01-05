mod commands;
use crate::commands::Runnable;
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
    bar_prefix: String,
    hostname: Option<String>,
    ip_address: String,
    mp: Arc<MultiProgress>,
}

impl TargetMachine {
    pub fn new(
        bar_prefix: String,
        hostname: Option<String>,
        ip_address: String,
        mp: Arc<MultiProgress>,
    ) -> TargetMachine {
        TargetMachine {
            bar_prefix,
            hostname,
            ip_address,
            mp,
        }
    }

    pub fn add_new_bar(&self) -> ProgressBar {
        let bar = self.mp.add(ProgressBar::new(0));
        let style = ProgressStyle::with_template("{msg}").unwrap();
        bar.set_style(style);
        bar
    }

    pub fn discovery(&self) {
        let ping_args = vec!["-c", "4", self.ip_address()];
        //let bar = self.add_new_bar();
        let ping = commands::DiscoveryCommand::new("ping", ping_args);
        //bar.set_message(format!("{} pinging", self.bar_prefix.clone()));
        ping.run_with_progress(ping.cli(), ping.args(), self.add_new_bar());
        //bar.finish_with_message(format!("{}DONE", self.bar_prefix.clone()))
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

pub struct DiscoveryCommand<'a> {
    os_command: &'a str,
    os_command_args: Vec<&'a str>,
    out_file: Option<&'a str>,
}

impl DiscoveryCommand<'_> {
    pub fn new<'a>(
        os_command: &'a str,
        os_command_args: Vec<&'a str>,
        out_file: Option<&'a str>,
    ) -> DiscoveryCommand<'a> {
        DiscoveryCommand {
            os_command_args,
            os_command,
            out_file,
        }
    }

    /*
    pub fn output_to_file(&self, file_owner: &IMDUser) {
        if let Ok(command_output) = self.run() {
            let mut f = match create_file_owned_by(self.out_file.as_ref().unwrap(), &file_owner) {
                Err(_) => {
                    let postfix = format!(
                        "Problem creating a file for the output of the `{}` command",
                        self.os_command
                    );
                    let postfix = format_command_result(&IMDOutcome::Bad, &postfix);
                    self.bar
                        .finish_with_message(format!("{}{postfix}", self.prefix));
                    return;
                }
                Ok(f) => f,
            };
            if writeln!(f, "{command_output}").is_err() {
                let postfix = format!(
                    "Problem writing results of the `{}` command to '{}'",
                    self.os_command,
                    self.out_file.as_ref().unwrap()
                );
                let postfix = format_command_result(&IMDOutcome::Bad, &postfix);
                self.bar
                    .finish_with_message(format!("{}{postfix}", self.prefix));
                return;
            }
        };
    }

    pub fn output_to_string(&self) -> Option<String> {
        self.bar.set_message(self.prefix.clone());
        let output = match self.run() {
            Err(_) => {
                let postfix = format!("Problem running the `{}` command", self.os_command);
                let postfix = format_command_result(&IMDOutcome::Bad, &postfix);
                self.bar
                    .finish_with_message(format!("{}{postfix}", self.prefix));
                return None;
            }
            Ok(output) => output,
        };
        let postfix = format_command_result(&IMDOutcome::Good, "Done");
        self.bar
            .finish_with_message(format!("{}{postfix}", self.prefix));

        Some(output)
    }
    */
}

pub fn create_file_owned_by(filename: &str, user: &IMDUser) -> Result<File, Box<dyn Error>> {
    // Create the desired file
    let f = File::create(filename)?;

    // Change ownership of the file to the logged in user that was grabbed in the Conf
    unistd::chown(filename, Some(*user.uid()), Some(*user.gid()))?;

    Ok(f)
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
pub fn format_command_result(outcome: &IMDOutcome, context: &str) -> StyledContent<String> {
    match outcome {
        IMDOutcome::Bad => format!("✕ {context}").red(),
        IMDOutcome::Good => format!("✔️ {context}").green(),
        IMDOutcome::Neutral => format!("〰 {context}").yellow(),
    }
}

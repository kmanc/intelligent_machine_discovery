use crossterm::style::Stylize;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use nix::unistd::{self, Gid, Uid};
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::process::Command;
use std::sync::Arc;

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

    fn create_results_dir(&self, user: &IMDUser) -> Result<(), Box<dyn Error>> {
        // If creating a directory fails, it's probably because the directory already exists (not 100%, but pretty likely), so report that and move on
        std::fs::create_dir(&self.ip_address)?;

        // Change ownership of the directory to the logged in user from Args
        unistd::chown(&self.ip_address[..], Some(*user.uid()), Some(*user.gid()))?;

        Ok(())
    }

    pub fn discovery(&self, user: &IMDUser) {
        self.create_results_dir(user);
        let ping = DiscoveryCommand::Ping;
        ping.run(&self.ip_address, self.add_new_bar(), &self.bar_prefix);
        let showmount = DiscoveryCommand::ShowmountDrives;
        showmount.run(&self.ip_address, self.add_new_bar(), &self.bar_prefix);
    }

    pub fn web_target(&self) -> String {
        match &self.hostname {
            Some(hostname) => hostname.to_string(),
            None => self.ip_address.to_string(),
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

#[derive(Debug)]
pub enum DiscoveryError {
    Connection,
}

impl DiscoveryError {
    pub fn as_str(&self) -> &'static str {
        match self {
            DiscoveryError::Connection => "Could not connect to host",
        }
    }
}

impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Error for DiscoveryError {}

pub enum DiscoveryCommand {
    FeroxbusterWeb,
    NiktoWeb,
    NmapAllTCP,
    NmapCommonTCP,
    Ping,
    ShowmountDrives,
}

impl DiscoveryCommand {
    fn args<'a>(&'a self, target: &'a str) -> Vec<&str> {
        match self {
            DiscoveryCommand::Ping => vec!["-c", "4", target],
            DiscoveryCommand::ShowmountDrives => vec!["-e", target],
            _ => todo!(),
        }
    }

    fn cli(&self) -> &str {
        match self {
            DiscoveryCommand::Ping => "ping",
            DiscoveryCommand::ShowmountDrives => "showmount",
            _ => todo!(),
        }
    }

    fn command(&self, target: &str) -> Result<String, Box<dyn Error>> {
        Ok(String::from_utf8(
            Command::new(self.cli())
                .args(self.args(target))
                .output()?
                .stdout,
        )?)
    }

    fn command_custom_failure(&self, target: &str) -> Result<String, Box<dyn Error>> {
        let output = self.command(target)?;

        for failure in &self.custom_failure_reasons() {
            if output.contains(failure) {
                return Err(Box::new(self.failure()));
            }
        }

        Ok(output)
    }

    fn command_custom_failure_with_progress(
        &self,
        target: &str,
        bar: ProgressBar,
        prefix: &str,
    ) -> String {
        bar.set_message(prefix.to_string());
        match self.command_custom_failure(target) {
            Ok(output) => {
                let postfix = "✔️ Done".to_string().green();
                bar.finish_with_message(format!("{prefix} {postfix}"));
                output
            }
            Err(err) => match err.downcast_ref::<DiscoveryError>() {
                Some(DiscoveryError::Connection) => {
                    let postfix = format!("✕ {err}").red();
                    bar.finish_with_message(format!("{prefix} {postfix}"));
                    String::new()
                }
                Some(_) => {
                    let postfix = format!("〰 {err}").yellow();
                    bar.finish_with_message(format!("{prefix} {postfix}"));
                    String::new()
                }
                None => {
                    let postfix = format!("✕ Problem running '{}' command", self.cli()).red();
                    bar.finish_with_message(format!("{prefix} {postfix}"));
                    String::new()
                }
            },
        }
    }

    fn command_to_file(&self, target: &str, outfile: File) -> Result<(), Box<dyn Error>> {
        Command::new(self.cli())
            .args(self.args(target))
            .stdout(outfile)
            .spawn()?;

        Ok(())
    }

    fn command_with_progress(&self, target: &str, bar: ProgressBar, prefix: &str) -> String {
        bar.set_message(prefix.to_string());
        match self.command(target) {
            Ok(output) => {
                let postfix = "✔️ Done".to_string().green();
                bar.finish_with_message(format!("{prefix} {postfix}"));
                output
            }
            Err(_) => {
                let postfix = format!("✕ Problem running '{}' command", self.cli()).red();
                bar.finish_with_message(format!("{prefix} {postfix}"));
                String::new()
            }
        }
    }

    fn custom_failure_reasons(&self) -> Vec<&str> {
        match self {
            DiscoveryCommand::Ping => vec!["100% packet loss", "100.0% packet loss"],
            _ => todo!(),
        }
    }

    fn failure(&self) -> DiscoveryError {
        match self {
            DiscoveryCommand::Ping => DiscoveryError::Connection,
            _ => todo!(),
        }
    }

    pub fn run(&self, target: &str, bar: ProgressBar, prefix: &str) -> String {
        match self {
            DiscoveryCommand::Ping => {
                let prefix = prefix.to_owned() + " Verifying connectivity";
                self.command_custom_failure_with_progress(target, bar, &prefix)
            }
            DiscoveryCommand::ShowmountDrives => {
                let prefix = prefix.to_owned() + " Looking for network drives with 'showmount'";
                self.command_with_progress(target, bar, &prefix)
            }
            _ => String::new(),
        }
    }
}

fn create_file_owned_by(filename: &str, user: &IMDUser) -> Result<File, Box<dyn Error>> {
    // Create the desired file
    let f = File::create(filename)?;

    // Change ownership of the file to the logged in user that was grabbed in the Conf
    unistd::chown(filename, Some(*user.uid()), Some(*user.gid()))?;

    Ok(f)
}

use crossterm::style::Stylize;
use indicatif::ProgressBar;
use std::error::Error;
use std::fmt;
use std::process::Command;

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

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Error for DiscoveryError {}

pub enum DiscoveryCommand {
    NmapAllTCP,
    Ping,
}

impl DiscoveryCommand {
    fn args<'a>(&'a self, target: &'a str) -> Vec<&str> {
        match self {
            DiscoveryCommand::Ping => vec!["-c", "4", target],
            DiscoveryCommand::NmapAllTCP => todo!(),
        }
    }

    fn cli(&self) -> &str {
        match self {
            DiscoveryCommand::Ping => "ping",
            DiscoveryCommand::NmapAllTCP => todo!(),
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

    fn command_custom_failure(
        &self,
        target: &str,
        how_to_fail: DiscoveryError,
    ) -> Result<String, Box<dyn Error>> {
        let output = self.command(target)?;

        for failure in &self.failures() {
            if output.contains(failure) {
                return Err(Box::new(how_to_fail));
            }
        }

        Ok(output)
    }

    fn command_custom_failure_with_progress(
        &self,
        target: &str,
        bar: ProgressBar,
        prefix: &str,
        how_to_fail: DiscoveryError,
    ) -> String {
        bar.set_message(prefix.to_string());
        match self.command_custom_failure(target, how_to_fail) {
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

    fn failures(&self) -> Vec<&str> {
        match self {
            DiscoveryCommand::Ping => vec!["100% packet loss", "100.0% packet loss"],
            DiscoveryCommand::NmapAllTCP => todo!(),
        }
    }

    pub fn run(&self, target: &str, bar: ProgressBar, prefix: &str) -> String {
        match self {
            DiscoveryCommand::Ping => self.command_custom_failure_with_progress(
                target,
                bar,
                prefix,
                DiscoveryError::Connection,
            ),
            _ => String::new(),
        }
    }
}

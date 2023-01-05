use crossterm::style::Stylize;
use indicatif::ProgressBar;
use std::error::Error;
use std::fmt;
use std::process::Command;

#[derive(Debug)]
pub enum DiscoveryError {
    AlreadyInHost,
    Connection,
}

impl DiscoveryError {
    pub fn as_str(&self) -> &'static str {
        match self {
            DiscoveryError::AlreadyInHost => "Entry already in '/etc/hosts'",
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

pub struct DiscoveryCommand<'a> {
    cli: &'a str,
    args: Vec<&'a str>,
}

impl DiscoveryCommand<'_> {
    pub fn new<'a>(cli: &'a str, args: Vec<&'a str>) -> DiscoveryCommand<'a> {
        DiscoveryCommand { cli, args }
    }

    pub fn run(&self) -> Result<String, Box<dyn Error>> {
        Ok(String::from_utf8(
            Command::new(self.cli).args(&self.args).output()?.stdout,
        )?)
    }

    pub fn run_custom_failure(
        &self,
        failures: Vec<&str>,
        how_to_fail: DiscoveryError,
    ) -> Result<String, Box<dyn Error>> {
        let output = self.run()?;

        for failure in &failures {
            if output.contains(failure) {
                return Err(Box::new(how_to_fail));
            }
        }

        Ok(output)
    }

    pub fn run_with_progress(&self, bar: ProgressBar, prefix: &str) -> String {
        bar.set_message(prefix.to_string());
        match self.run() {
            Ok(output) => {
                let postfix = "✔️ Done".to_string().green();
                bar.finish_with_message(format!("{prefix} {postfix}"));
                output
            }
            Err(_) => {
                let postfix = format!("✕ Problem running '{}' command", self.cli).red();
                bar.finish_with_message(format!("{prefix} {postfix}"));
                String::new()
            }
        }
    }

    pub fn run_custom_failure_with_progress(
        &self,
        bar: ProgressBar,
        prefix: &str,
        failures: Vec<&str>,
        how_to_fail: DiscoveryError,
    ) -> String {
        bar.set_message(prefix.to_string());
        match self.run_custom_failure(failures, how_to_fail) {
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
                Some(DiscoveryError::AlreadyInHost) => {
                    let postfix = format!("〰 {err}").yellow();
                    bar.finish_with_message(format!("{prefix} {postfix}"));
                    String::new()
                },
                None => {
                    let postfix = format!("✕ Problem running '{}' command", self.cli).red();
                    bar.finish_with_message(format!("{prefix} {postfix}"));
                    String::new()
                }
            },
        }
    }
}

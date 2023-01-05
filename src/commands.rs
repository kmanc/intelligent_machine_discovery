use indicatif::ProgressBar;
use std::error::Error;
use std::process::Command;

pub struct DiscoveryCommand<'a> {
    cli: &'a str,
    args: Vec<&'a str>,
}

impl DiscoveryCommand<'_> {
    pub fn new<'a>(cli: &'a str, args: Vec<&'a str>) -> DiscoveryCommand<'a> {
        DiscoveryCommand {
            cli,
            args,
        }
    }

    pub fn cli<'a>(&self) -> &str {
        &self.cli
    }

    pub fn args<'a>(&self) -> Vec<&str> {
        self.args.clone()
    }
}

impl Runnable for DiscoveryCommand<'_> {}

pub trait Runnable {
    fn run(&self, cli: &str, args: Vec<&str>) -> Result<String, Box<dyn Error>> {
        Ok(String::from_utf8(
            Command::new(cli).args(args).output()?.stdout,
        )?)
    }

    fn run_with_progress(&self, cli: &str, args: Vec<&str>, bar: ProgressBar) -> String {
        bar.set_message("STARTING");
        match self.run(cli, args) {
            Ok(output) => {
                bar.finish_with_message("FINISHED OK");
                output
            }
            Err(_) => {
                bar.finish_with_message("FINISHED ERROR");
                String::new()
            }
        }
    }
}

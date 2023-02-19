use clap::{self, Arg, Command, ValueHint};
use indicatif::MultiProgress;
use std::sync::Arc;

pub struct Conf {
    target_machines: Vec<imd::TargetMachine>,
    user: Arc<imd::IMDUser>,
    wordlist: Arc<String>,
}

impl Conf {
    pub fn init() -> Conf {
        // Create a multiprogress container for printing things to throughout the running of imd
        let mp = Arc::new(MultiProgress::new());

        let bar = imd::add_new_bar(mp.clone());

        // imd must be run as root to work - ensure that's the case here, after other matching issues (if any) have been surfaced
        if let Err(e) = imd::effective_user() {
            bar.finish_with_message(format!("{e}"));
            std::process::exit(0x1);
        }

        // find the logged in user (probably the one running imd) in order to deal with created file permissions later
        let user = Arc::new(imd::real_user().unwrap());

        // Use clap to parse command line args
        let app = cli();
        let matches = app.get_matches();

        // Collect all of the target machines into a vector
        let target_machines: Vec<&imd::CLITarget> = matches
            .get_many::<imd::CLITarget>("targets")
            .unwrap()
            .collect();

        // Figure out the length of the longest target machine by IP address (for printing purposes)
        let longest_ip = target_machines
            .clone()
            .iter()
            .max_by(|&x, &y| x.len().cmp(&y.len()))
            .unwrap()
            .len();

        let target_machines: Vec<imd::TargetMachine> = target_machines
            .into_iter()
            .map(|cli_machine| imd::TargetMachine::new(cli_machine.clone(), longest_ip, mp.clone()))
            .collect();

        // Get the wordlist, which is either user-provided or a default value
        let wordlist = Arc::new(matches.get_one::<String>("wordlist").unwrap().to_string());

        bar.finish_with_message(format!(
            "Starting discovery on {} target machines",
            target_machines.len()
        ));

        Conf {
            target_machines,
            user,
            wordlist,
        }
    }

    pub fn target_machines(&self) -> &Vec<imd::TargetMachine> {
        &self.target_machines
    }

    pub fn user(&self) -> Arc<imd::IMDUser> {
        self.user.clone()
    }

    pub fn wordlist(&self) -> Arc<String> {
        self.wordlist.clone()
    }
}

fn cli() -> Command {
    let app = clap::Command::new(clap::crate_name!())
        .version(clap::crate_version!())
        .author(clap::crate_authors!())
        .about(clap::crate_description!());

    app.arg(
        Arg::new("targets")
            .short('t')
            .value_name("TARGET_MACHINES")
            .num_args(1..)
            .required(true)
            .value_hint(ValueHint::CommandString)
            .value_parser(clap::builder::ValueParser::new(imd::CLITarget::new))
            .help("Target machine(s)'s IP address(es), optionally with =hostname: E.G. 127.0.0.1 OR 127.0.0.1=myhostname")
    )
    .arg(
        Arg::new("wordlist")
            .short('w')
            .value_name("WORDLIST")
            .num_args(1)
            .value_hint(ValueHint::FilePath)
            .default_value("/Users/koins/Documents/github/rust/testing/.gitignore")
            .value_parser(clap::builder::ValueParser::new(imd::wrap_wordlist_parse))
            .help("Wordlist for web discovery"),
    )
}

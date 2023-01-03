use clap::{self, Arg, ValueHint};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use nix::unistd::{Gid, Uid, User};
use std::iter;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

pub struct Conf {
    machines: Vec<imd::TargetMachine>,
    user: imd::IMDUser,
    wordlist: String,
}

impl Conf {
    pub fn init() -> Option<Conf> {
        // Set up the command line arguments and their associated settings
        let app = cli();

        // Parse what the user entered
        let matches = app.get_matches();

        // Create a multiprogress container for printing things to
        let mp = Arc::new(MultiProgress::new());

        // Create a bar for validating the inputs that clap can't
        let bar = mp.add(ProgressBar::new(0));
        let style = ProgressStyle::with_template("{msg}").unwrap();
        bar.set_style(style);

        // Inform user that inputs are being validated
        let starter = "Validating imd configuration ";
        bar.set_message(starter);

        // imd must be run as root to work - ensure that's the case here, after other matching issues (if any) have been surfaced
        if !Uid::effective().is_root() {
            let outcome = imd::format_command_result(
                &imd::IMDOutcome::Bad,
                "imd must be run with root permissions, please try running 'sudo !!'",
            );
            bar.finish_with_message(format!("{starter}{outcome}"));
            return None;
        }

        // Run the who command to determine the logged in user (hopefully the person who ran imd)
        let name = std::process::Command::new("who").output().unwrap();
        let name = String::from_utf8(name.stdout).unwrap();
        let name = String::from(name.split(' ').collect::<Vec<&str>>()[0]);

        // Get the user ID from the username
        let (uid, gid) = match User::from_name(&name).unwrap() {
            None => (Uid::from_raw(0), Gid::from_raw(0)),
            Some(user) => (user.uid, user.gid),
        };

        // Create an IMD user that will be used to do file permissions work later on
        let user = imd::IMDUser::new(gid, name, uid);

        // Set an empty vec for target machines
        let mut machines: Vec<imd::TargetMachine> = vec![];

        // Get the target IP addresses but convert them to strings because we won't actually need them for anything other than printing
        let ip_addresses: Vec<String> = matches
            .get_many::<IpAddr>("targets")
            .unwrap()
            .map(|ip| ip.to_string())
            .collect();

        // Find the longest IP address entered
        let longest = ip_addresses
            .iter()
            .max_by(|&x, &y| x.len().cmp(&y.len()))
            .unwrap();

        // Add one to it's length for formatting the output of commands run later on
        let print_pad = longest.len() + 1;

        // Get the target names, or an empty vector if None
        let mut names: Vec<Option<String>> = match matches.try_get_many::<String>("names").unwrap()
        {
            None => vec![],
            Some(names) => names.map(|s| Some(String::from(s))).collect(),
        };

        // Pad the names list with None until it's the same length as IP addresses
        names.resize_with(ip_addresses.len(), || None);

        // Add all the IP addresses to the target machine list with the associates hostnames (if any)
        for (ip_address, name) in iter::zip(ip_addresses, names) {
            machines.push(imd::TargetMachine::new(
                name,
                ip_address,
                mp.clone(),
                print_pad,
            ))
        }

        // Get the wordlist, which will either be the user-provided option or the default value
        let wordlist = matches.get_one::<String>("wordlist").unwrap().to_string();

        // Make sure the path is a real file on the user's drive
        if !Path::new(&wordlist).exists() {
            let outcome = imd::format_command_result(
                &imd::IMDOutcome::Bad,
                &format!("'{wordlist}' is not a valid filepath "),
            );
            bar.finish_with_message(format!("{starter}{outcome}"));
            return None;
        }

        let outcome = imd::format_command_result(&imd::IMDOutcome::Good, "Done");
        bar.finish_with_message(format!("{starter}{outcome}"));

        // Return the args, which includes the target machines, the logged in user, and the wordlist
        Some(Conf {
            machines,
            user,
            wordlist,
        })
    }

    pub fn machines(&self) -> &Vec<imd::TargetMachine> {
        &self.machines
    }

    pub fn user(&self) -> imd::IMDUser {
        self.user.clone()
    }

    pub fn wordlist(&self) -> &str {
        &self.wordlist
    }
}

fn cli() -> clap::Command {
    let app = clap::Command::new(clap::crate_name!())
        .version(clap::crate_version!())
        .author(clap::crate_authors!())
        .about(clap::crate_description!());

    app.arg(
        Arg::new("targets")
            .short('t')
            .value_name("IP_ADDRESS")
            .value_parser(clap::value_parser!(IpAddr))
            .num_args(1..)
            .value_hint(ValueHint::CommandString)
            .required(true)
            .help("Target machine(s)'s IP address(es)"),
    )
    .arg(
        Arg::new("names")
            .short('n')
            .value_name("NAME")
            .num_args(1..)
            .value_hint(ValueHint::CommandString)
            .help("Target machine(s)'s name(s)"),
    )
    .arg(
        Arg::new("wordlist")
            .short('w')
            .value_name("WORDLIST")
            .num_args(1)
            .value_hint(ValueHint::FilePath)
            .default_value("/usr/share/wordlists/seclists/raft-medium-directories.txt")
            .help("Wordlist for web discovery"),
    )
}

use clap::{crate_authors, crate_description, crate_name, crate_version, Arg, Command, ValueHint};
use nix::unistd::{Gid, Uid, User};
use std::env;
use std::iter::zip;
use std::net::IpAddr;
use std::sync::Arc;

pub struct Conf {
    machines: Vec<imd::TargetMachine>,
    user: Arc<imd::IMDUser>,
    wordlist: Arc<String>,
}

impl Conf {
    pub fn init() -> Conf {
        // Set up the command line arguments and their associated settings
        let app = cli();

        // Parse what the user entered
        let matches = app.get_matches();

        // imd must be run as root to work - ensure that's the case here, after other matching issues (if any) have been surfaced
        if !Uid::effective().is_root() {
            let error = imd::report(
                imd::IMDOutcome::Bad,
                "imd must be run with root permissions, please try running 'sudo!!'",
            );
            panic!("{error}")
        }

        // Set an empty vec for target machines
        let mut machines: Vec<imd::TargetMachine> = vec![];

        // Get the target machines parsed as IP addresses
        let ip_addresses: Vec<_> = matches
            .get_many::<String>("targets")
            .unwrap()
            .map(|s| s.parse::<IpAddr>())
            .collect();

        // Get the target names, or an empty vector if None
        let mut names: Vec<_> = match matches.get_many::<String>("names") {
            None => vec![],
            Some(names) => names.map(|s| Some(s.to_string())).collect(),
        };

        // Pad the names list with None until it's the same length as IP addresses
        names.resize_with(ip_addresses.len(), || None);

        // Add all the valid IP addresses to the target machine list with the associates hostnames
        for (ip_address, name) in zip(ip_addresses, names) {
            match ip_address {
                Ok(ip_address) => machines.push(imd::TargetMachine::new(name, ip_address)),
                Err(_) => {
                    let log = imd::report(
                        imd::IMDOutcome::Bad,
                        "Oooops, an entered IP addresses wasn't actually an IP address, skipping it"
                    );
                    println!("{log}");
                }
            }
        }

        // Run the who command to determine the logged in user (hopefully the person who ran imd)
        let name = imd::get_command_output("who", [].to_vec()).unwrap();
        let name = String::from(name.split(' ').collect::<Vec<&str>>()[0]);

        // Get the user ID from the username
        let (uid, gid) = match User::from_name(&name).unwrap() {
            Some(user) => (user.uid, user.gid),
            _ => (Uid::from_raw(0), Gid::from_raw(0)),
        };

        let user = imd::IMDUser::new(gid, name, uid);

        // Get the wordlist, which will either be the user-provided option or the default value
        let wordlist = matches.get_one::<String>("wordlist").unwrap().to_string();

        // Return the args, which includes the target machines, the logged in user, and the wordlist
        Conf {
            machines,
            user: Arc::new(user),
            wordlist: Arc::new(wordlist),
        }
    }

    pub fn machines(&self) -> &Vec<imd::TargetMachine> {
        &self.machines
    }

    pub fn user(&self) -> &Arc<imd::IMDUser> {
        &self.user
    }

    pub fn wordlist(&self) -> &Arc<String> {
        &self.wordlist
    }
}

fn cli() -> Command {
    let app = Command::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!());

    app
        .arg(
            Arg::new("targets")
                .short('t')
                .long("targets")
                .value_name("IP_ADDRESS")
                .num_args(1..)
                .value_hint(ValueHint::CommandString)
                .required(true)
                .help("Target machine(s)'s IP address(es)"),
        )
        .arg(
            Arg::new("names")
                .short('n')
                .long("names")
                .value_name("NAME")
                .num_args(1..)
                .value_hint(ValueHint::CommandString)
                .help("Target machine(s)'s name(s)"),
        )
        .arg(
            Arg::new("wordlist")
                .short('w')
                .long("wordlist")
                .value_name("WORDLIST")
                .num_args(1)
                .value_hint(ValueHint::FilePath)
                .default_value("/usr/share/wordlists/seclists/raft-medium-directories.txt")
                .help("Wordlist for web discovery"),
        )
}

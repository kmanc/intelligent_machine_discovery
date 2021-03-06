/*
 Author: Kevin Conley <kmancxc@gmail.com>
 GitHub: https://github.com/kmanc/
*/

use imd::Config;
use std::env;
use std::io::{self, Write};
use std::process;
use std::sync::Arc;
use std::thread;


fn main() {
    // Check to see if the user was sudo - if we got an error, alert the user and exit
    if let Err(e) = imd::sudo_check() {
        eprintln!("{}", e);
        process::exit(1);
    }

    // Collect the command line args
    let args: Vec<String> = env::args().collect();
    // Get the user entered IP address(es) and optionally hostname(s)
    let config = Config::new(&args);
    let config = match config {
        Ok(config) => config,
        Err(e) => {
            eprintln!("{}", e);
            process::exit(1);
        }
    };

    let username = config.username();
    let username = Arc::new(username.to_owned());
    let mut threads = vec![];

    for target_machine in config.targets().iter().cloned() {
        threads.push(thread::spawn({
            let username = Arc::clone(&username);
            move || {
                if let Err(e) = imd::target_discovery(&target_machine, username) {
                    eprintln!("{}", e);
                }
            }
        }));

    }

    for t in threads {
        t.join().unwrap();
    }

    // Fix stdout because it somehow gets messed up
    println!("All machine scans complete");
    io::stdout().flush().unwrap();
}
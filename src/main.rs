/*
 Author: Kevin Conley <kmancxc@gmail.com>
 GitHub: https://github.com/kmanc/
*/

use std::collections::HashMap;
use std::env;
use std::io::{self, Write};
use std::process;

use imd::Config;


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

    for target_machine in config.targets().iter() {
        if let Err(e) = imd::target_discovery(target_machine, username) {
            eprintln!("{}", e);
        }
    }

    // Fix stdout because it somehow gets messed up
    io::stdout().flush().unwrap();
}
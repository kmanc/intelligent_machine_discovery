/*
 Author: Kevin Conley <kmancxc@gmail.com>
 GitHub: https://github.com/kmanc/
*/

use imd::Config;
use std::env;
use std::io::{self, Write};
use std::process;
use std::sync::{Arc, mpsc};
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
    let (tx, rx) = mpsc::channel();
    let mut threads = vec![];

    for target_machine in config.targets().iter().cloned() {
        threads.push(thread::spawn({
            let tx = tx.clone();
            let username = Arc::clone(&username);
            move || {
                if let Err(e) = imd::target_discovery(&target_machine, username, tx) {
                    eprintln!("{}", e);
                }
            }
        }));

    }

    // Drop the main thread's transmitter or runtime will hang
	drop(tx);

    // Capture the messages sent across the channel
    for received in rx {
        println!("{}", received);
        // In case stdout got messed up somehow, flush it to fix
        io::stdout().flush().unwrap();
    }

    for t in threads {
        t.join().unwrap();
    }

    println!("All machine scans complete");
    // In case stdout got messed up somehow, flush it to fix
    io::stdout().flush().unwrap();
}
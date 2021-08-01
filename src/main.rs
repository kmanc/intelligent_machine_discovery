/*
 Author: Kevin Conley <kmancxc@gmail.com>
 GitHub: https://github.com/kmanc/
*/

use imd::Config;
use std::env;
use std::io::Write;
use std::process;
use std::sync::{Arc, mpsc};
use std::thread;
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};


fn main() {
    // Create send/receive channels
    let (tx, rx) = mpsc::channel();

    // Check to see if the user was sudo - if we got an error, alert the user and exit
    match imd::sudo_check() {
        Err(e) => tx.send(e.to_string()).unwrap(),
        _ => ()
    }

    // Collect the command line args
    let args: Vec<String> = env::args().collect();
    // Get the user entered IP address(es) and optionally hostname(s)
    let config = match Config::new(&args) {
        Ok(config) => config,
        Err(e) => {
            tx.send(e.to_string()).unwrap();
            Config::new(&vec!["FakeCommand".to_string(), "0.0.0.0".to_string()]).unwrap()
        }
    };

    let username = config.username();
    let username = Arc::new(username.to_owned());
    let mut threads = vec![];

    for target_machine in config.targets().iter().cloned() {
        threads.push(thread::spawn({
            let tx = tx.clone();
            let username = Arc::clone(&username);
            move || {
                if let Err(e) = imd::target_discovery(&target_machine, username, tx.clone()) {
                    tx.send(e.to_string()).unwrap();
                }
            }
        }));
    }

    // Drop the main thread's transmitter or execution will hang at runtime
	drop(tx);
    // Set up stdout for colorized printing
    let mut stdout = StandardStream::stdout(ColorChoice::Always);
    let mut stderr = StandardStream::stderr(ColorChoice::Always);

    // Capture the messages sent across the channel
    for received in rx {
        // Split on space dash space
        let color_test: Vec<&str> = received.split(" - ").collect();
        // Check to see if this is a fatal error
        if color_test[0] == ("Fatal") {
            // Set stderr to Red
            stderr.set_color(ColorSpec::new().set_fg(Some(Color::Rgb(255, 0, 0)))).ok();
            // Gracefully tear down after printing fatal error
            writeln!(&mut stderr, "{}", received).unwrap();
            stderr.reset().ok();
            process::exit(1);
        }
        // Since it isn't fatal, continue processing by grabbing the next portion
        let color_test = color_test[1];
        let color_test: Vec<&str> = color_test.split(" ").collect();
        // Grab the first word in that portion
        let color_test = color_test[0];
        if color_test.ends_with("ing") {
            // Stdout --> Yellow
            stdout.set_color(ColorSpec::new().set_fg(Some(Color::Rgb(255, 255, 0)))).ok();
        } else if color_test.ends_with("ed") {
            // Stdout --> Green
            stdout.set_color(ColorSpec::new().set_fg(Some(Color::Rgb(0, 204, 0)))).ok();
        } else {
            // Stderr --> Red
            stderr.set_color(ColorSpec::new().set_fg(Some(Color::Rgb(255, 0, 0)))).ok();
            // Write to stderr, not stdout
            writeln!(&mut stderr, "{}", received).unwrap();
            // Skip to the next message
            continue;
        }
        writeln!(&mut stdout, "{}", received).unwrap();
    }

    for t in threads {
        t.join().unwrap();
    }

    // Reset the terminal color
    stdout.reset().ok();
    stderr.reset().ok();
    println!("All machine scans complete");
}
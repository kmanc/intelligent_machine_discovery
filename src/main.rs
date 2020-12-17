/*
 Author: Kevin Conley <kmancxc@gmail.com>
 GitHub: https://github.com/kmanc/
*/

use std::collections::HashMap;
use std::env;
use std::io::{self, Write};
use std::process;
//use std::sync::{Arc, Mutex};
//use std::thread;

use imd::{Config, TargetMachine};


fn main() {
    // Check to see if the user was sudo
    // If we got an error, alert the user and exit
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

    let targets = config.targets();

    println!("Targets: {:?}", targets);
    // Just take the first target for now
    let first_target = &targets[0];
    // Just take the first IP address for now
    let ip_address = &targets[0].ip().to_string();
    // Just take the first hostname if it was entered
    let hostname = &String::from(targets[0].hostname().as_deref().unwrap_or(&String::from("None")));
    // Just take the username for now
    let username = config.username();

    // Ping the machine to make sure it is alive
    println!("Verifying connectivity to {}", ip_address);
    if let Err(e) = first_target.check_connection() {
        eprintln!("{}", e);
        process::exit(1);
    }

    // Create directory for storing things in
    println!("Creating directory \"{}\" to store resulting files in", ip_address);
    if let Err(e) = imd::create_dir(username,&ip_address) {
        eprintln!("{}", e);
        process::exit(1);
    }

    println!("TODO: uncomment the showmount and TCP all scans when I don't need fast testing");
    /*
    // nmap scan on all tcp ports
    println!("Scanning all TCP ports");
    if let Err(e) = first_target.nmap_scan_all_ports(&username) {
        eprintln!("{}", e);
    }

    // showmount scan
    println!("Listing all NFS shares");
    if let Err(e) = first_target.showmount_scan(&username) {
        eprintln!("{}", e);
    }

     */

    //
    if first_target.hostname().is_some() {
        if let Err(e) = first_target.add_to_hosts() {
            eprintln!("{}", e);
        }
    }

    // Run a basic nmap scan with service discovery
    println!("Running \"nmap -sV {}\" for basic target information", ip_address);
    let parsed_nmap = first_target.nmap_scan_basic(&username);
    let parsed_nmap = match parsed_nmap {
        Ok(parsed_nmap) => parsed_nmap,
        Err(e) => {
            eprintln!("{}", e);
            None
        }
    };

    let hostname = match first_target.hostname() {
        Some(hostname) => Some(String::from(hostname)),
        None => None
    };

    let first_target = TargetMachine::new(*first_target.ip(), hostname, parsed_nmap);


    println!("POST NMAP SCAN {:?}", &first_target);

    println!("\tCompleted planning next steps based on nmap scan");

    match first_target.services() {
        Some(services) => {
            if services.contains_key("http") {
                println!("we have some http ports! {:?}", services.get("http").unwrap())
            }
            if services.contains_key("ssl/http") {
                println!("we have some https ports! {:?}", services.get("ssl/http").unwrap())
            }
        },
        None => ()
    }

    println!("TODO: uncomment the lines about web when ready to test on Kali");
    // Make a vector of IP and hostname for easier iteration
    /*
    for port in parsed_nmap.http.iter() {
        let web_targets: Vec<String> = vec![ip_address.clone(), hostname.clone()];
        for web_host in web_targets.iter() {
            println!("Running nikto scan on {}:{}", &web_host, &port);
            if let Err(e) = first_target.nikto_scan(&username, &web_host, &port) {
                eprintln!("Nikto issue {}", e);
            }

            println!("Running gobuster scans on {}:{}", &web_host, &port);

            let gobuster = first_target.gobuster_scan(&username, &web_host, &port);
            let gobuster = match gobuster {
                Ok(gobuster) => gobuster,
                Err(e) => {
                    eprintln!("Gobuster Issue {}", e);
                    vec![]
                }
            };

            for dir in gobuster.iter() {
                println!("Running gobuster scans on {}:{}{}", &web_host, &port, &dir);
                let wfuzz = first_target.wfuzz_scan(&web_host, &port, &dir);
                let wfuzz = match wfuzz {
                    Ok(wfuzz) => wfuzz,
                    Err(e) => {
                        eprintln!("{}", e);
                        vec![]
                    }
                };
                println!("WFUZZ: {:?}", wfuzz);
            }
        }
    }
    */

    // Fix stdout because it somehow gets messed up
    io::stdout().flush().unwrap();
}
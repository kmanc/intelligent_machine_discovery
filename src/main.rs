/*
 Author: Kevin Conley <kmancxc@gmail.com>
 GitHub: https://github.com/kmanc/
*/

use std::env;
use std::error::Error;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::net::IpAddr;
use std::process::{self, Command};
use std::sync::{Arc, Mutex};
use std::thread;

use imd::{Config, ServicePorts, TargetMachine};


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

    let targets = &config.targets;

    println!("Targets: {:?}", targets);
    // Just take the first target for now
    let first_target = &targets[0];
    // Just take the first IP address for now
    let ip_address = &targets[0].ip.to_string();
    // Just take the first hostname if it was entered
    let hostname = &String::from(targets[0].hostname.as_deref().unwrap_or("None"));
    // Just take the username for now
    let username = &config.username;

    // Ping the machine to make sure it is alive
    println!("Verifying connectivity to {}", ip_address);
    if let Err(e) = first_target.check_connection() {
        eprintln!("{}", e);
        process::exit(1);
    }

    // Create directory for storing things in
    println!("Creating directory \"{}\" to store resulting files in", ip_address);
    if let Err(e) = config.create_dir(&ip_address) {
        eprintln!("{}", e);
        process::exit(1);
    }

    // nmap scan on all tcp ports
    println!("Kicking off thread for scanning all TCP ports");
    if let Err(e) = first_target.nmap_scan_all_ports(&username) {
        eprintln!("{}", e);
    }

    // showmount scan
    println!("Kicking off thread for listing NFS shares");
    if let Err(e) = first_target.showmount_scan(&username) {
        eprintln!("{}", e);
    }

    //
    if first_target.hostname.is_some() {
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
            // TODO remove this and replace it with just empty ServicePorts instance?
            process::exit(1);
        }
    };


    // Report on all discovered ftp ports
    if !parsed_nmap.ftp.is_empty(){
        println!("\tFtp found on port(s) {:?}", &parsed_nmap.ftp)
    }

    // Report on all discovered http ports
    if !parsed_nmap.http.is_empty(){
        println!("\tHttp found on port(s) {:?}", &parsed_nmap.http)
    }

    // Report on all discovered https ports
    if !parsed_nmap.https.is_empty(){
        println!("\tHttps found on port(s) {:?}", &parsed_nmap.https)
    }
    println!("\tCompleted planning next steps based on nmap scan");

    // Make a vector of IP and hostname for easier iteration
    for port in parsed_nmap.http.iter() {
        let web_targets: Vec<String> = vec![ip_address.clone(), hostname.clone()];
        for web_host in web_targets.iter() {
            println!("Kicking off thread for nikto scan on {}:{}", &web_host, &port);
            if let Err(e) = first_target.nikto_scan(&username, &web_host, &port) {
                eprintln!("{}", e);
            }

            println!("Kicking off thread for gobuster/wfuzz scans on {}:{}", &web_host, &port);
            if let Err(e) = first_target.gobuster_wfuzz_scans(&username, &web_host, &port) {
                eprintln!("{}", e);
            }
        }
    }

    // Fix stdout because it somehow gets messed up
    io::stdout().flush().unwrap();
}
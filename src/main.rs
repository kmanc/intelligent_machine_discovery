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

    // Create a vector for threads so we can keep track of them and join on them all at the end
    let mut threads = Vec::new();

    // Spawn thread for nmap scan on all tcp ports
    println!("Kicking off thread for scanning all TCP ports");
    threads.push(thread::spawn({
        // Clone variables so the thread can use them without borrowing/ttl issues
        let (tcp_thread_username, tcp_thread_ip) = (config.username.clone(), ip_address.clone());
        move|| {
            run_tcp_all_nmap(&tcp_thread_username, &tcp_thread_ip);
        }
    }));

    // Spawn thread for showmount scan
    println!("Kicking off thread for listing NFS shares");
    threads.push(thread::spawn({
        // Clone variables so the thread can use them without borrowing/ttl issues
        let (showmount_thread_username, showmount_thread_ip) = (config.username.clone(), ip_address.clone());
        move|| {
            run_showmount(&showmount_thread_username, &showmount_thread_ip);
        }
    }));

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
            // TODO remove this and replace it with just empty ServicePorts instance
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
            threads.push(thread::spawn({
                // Clone variables so the thread can use them without borrowing/ttl issues
                let (nikto_thread_username, nikto_thread_ip, nikto_thread_host, nikto_thread_port) = (config.username.clone(), ip_address.clone(), web_host.clone(), port.clone());
                move || {
                    run_nikto(&nikto_thread_username, &nikto_thread_ip, &nikto_thread_host, &nikto_thread_port);
                }
            }));
            println!("Kicking off thread for gobuster/wfuzz scans on {}:{}", &web_host, &port);
            threads.push(thread::spawn({
                // Clone variables so the thread can use them without borrowing/ttl issues
                let (web_thread_username, web_thread_ip, web_thread_host, web_thread_port) = (config.username.clone(), ip_address.clone(), web_host.clone(), port.clone());
                move || {
                    run_gobuster_wfuzz(&web_thread_username, &web_thread_ip, &web_thread_host, &web_thread_port);
                }
            }));
        }
    }


    // Wait for all outstanding threads to finish
    for thread in threads {
        thread.join().unwrap();
    }

    // Fix stdout because it somehow gets messed up
    io::stdout().flush().unwrap();
}


fn create_output_file(username: &str, filename: &String) -> Result<(), String> {

    // Create a file as the provided user with the desired name
    let touch = Command::new("sudo")
                        .arg("-u")
                        .arg(username)
                        .arg("touch")
                        .arg(filename)
                        .output();

    match touch {
        Err(err) => return Err(format!("Failed to create file {}: {}", filename, err)),
        _ => ()
    }

    Ok(())
}


fn run_tcp_all_nmap(username: &str, ip_address: &str) {
    let filename = format!("{}/nmap_all_tcp", ip_address);
    let create = create_output_file(username, &filename);
    match create {
        Ok(_) => (),
        Err(err) => println!("{}", err)
    }

    // Obtain a file handle with write permissions
    let file_handle = OpenOptions::new()
                                  .write(true)
                                  .open(&filename);

    match file_handle {
        Ok(file_handle) => {
            // Run an nmap command with -p-, and use the file handle for stdout
            let nmap = Command::new("nmap")
                               .arg("-p-")
                               .arg(ip_address)
                               .stdout(file_handle)
                               .output();
            match nmap {
                Ok(_) => println!("\tCompleted nmap scan for all TCP ports"),
                Err(err) => println!("\t\"nmap -p-\" command failed to run: {}", err)
            }
        },
        Err(err) => println!("Problem obtaining handle to {}: {}", filename, err),
    }
}


fn run_showmount(username: &str, ip_address: &str) {
    let filename = format!("{}/nfs_shares", ip_address);
    let create = create_output_file(username, &filename);
    match create {
        Ok(_) => (),
        Err(err) => println!("{}", err)
    }

    // Obtain a file handle with write permissions
    let file_handle = OpenOptions::new()
                                  .write(true)
                                  .open(&filename);

    match file_handle {
        Ok(file_handle) => {
            // Run the showmount command with -e, and use the file handle for stdout
            let showmount = Command::new("showmount")
                                    .arg("-e")
                                    .arg(ip_address)
                                    .stdout(file_handle)
                                    .output();

            match showmount {
                Ok(_) => println!("\tCompleted showmount scan for NFS shares"),
                Err(err) => println!("\t\"showmount -e\" command failed to run: {}", err)
            }
        },
        Err(err) => println!("Problem obtaining handle to {}: {}", filename, err),
    }

    println!("\tCompleted scan for NFS shares");
}


fn run_nikto(username: &str, ip_address: &str, target: &str, port: &str) {
    let filename = format!("{}/nikto_{}:{}", &ip_address, &target, &port);
    let target = String::from(target);
    let port = String::from(port);
    let create = create_output_file(username, &filename);
    match create {
        Ok(_) => (),
        Err(err) => println!("{}", err)
    }

    println!("Starting a nikto scan on {}:{}", &target, &port);

    // Obtain a file handle with write permissions
    let file_handle = OpenOptions::new()
                                  .write(true)
                                  .open(&filename);

    match file_handle {
        Ok(file_handle) => {
            // Run the nikto command with a bunch of flags, and use the file handle for stdout
            let nikto = Command::new("nikto")
                                .arg("-host")
                                .arg(&target)
                                .arg("-port")
                                .arg(&port)
                                .stdout(file_handle)
                                .output();

            match nikto {
                Ok(_) => println!("\tNikto scan on {}:{} complete!", &target, &port),
                Err(err) => println!("\tFailed to run nikto scan on {}:{}: {}", &target, &port, err)
            }
        },
        Err(err) => println!("Problem obtaining handle to {}: {}", filename, err),
    }

    println!("\tCompleted nikto scan on {}:{}", &target, &port);
}


fn run_gobuster_wfuzz(username: &str, ip_address: &str, target: &str, port: &str) {
    let filename = format!("{}/dirs_{}:{}", &ip_address, &target, &port);
    let target = String::from(target);
    let port = String::from(port);
    let create = create_output_file(username, &filename);
    match create {
        Ok(_) => (),
        Err(err) => println!("{}", err)
    }

    println!("Starting gobuster directory scan on {}:{}", &target, &port);

    // Obtain a file handle with write permissions
    let file_handle = OpenOptions::new()
                                  .write(true)
                                  .open(&filename);

    let gobuster = match file_handle {
        Ok(file_handle) => {
            // Run gobuster with a slew of flags
            let gobuster_arg = format!("http://{}:{}", &target, &port);
            let gobuster = Command::new("gobuster")
                                   .arg("dir")
                                   .arg("-q")
                                   .arg("-t")
                                   .arg("25")
                                   .arg("-r")
                                   .arg("-w")
                                   .arg("/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt")
                                   .arg("-u")
                                   .arg(&gobuster_arg)
                                   .stdout(file_handle)
                                   .output();

            let gobuster = match gobuster {
                Ok(gobuster) => {
                    // Grab the output and convert it to a string
                    let gobuster = String::from_utf8(gobuster.stdout).unwrap();
                    // Remove whitespace
                    let gobuster = gobuster.trim();
                    // Convert it to a vector by splitting on newlines and allow it to be mutable
                    let mut gobuster: Vec<String> = gobuster.split("\n")
                                                          .map(|s| s.trim().to_string())
                                                          .collect();
                    // Make sure at a bare minimum the empty string is in there so we will scan the root dir
                    if !gobuster.iter().any(|i| i == "") {
                        gobuster.push(String::from(""));
                    }

                    gobuster
                },
                Err(err) => {
                    println!("Failed to run gobuster on {}: {}", gobuster_arg, err);

                    vec![String::from("")]
                }
            };

            println!("\tCompleted gobuster scan for {}:{}", &target, &port);

            gobuster
        },
        Err(err) => {
            println!("Problem obtaining handle to {}: {}", filename, err);
            vec![String::from("")]
        },
    };

    // We're going to spin up a bunch of threads that need to share a common output
    let wfuzz_result = Arc::new(Mutex::new(vec![]));
    let mut wfuzz_handles = vec![];

    for dir in gobuster.iter() {
        println!("Starting wfuzz scan for http://{}:{}{}/", &target, &port, &dir);

        wfuzz_handles.push(thread::spawn({
            let wfuzz_result = Arc::clone(&wfuzz_result);
            let (thread_target, thread_port, thread_dir) = (target.clone(), port.clone(), dir.clone());
            move || {
                let mut thread_result = wfuzz_result.lock().unwrap();

                let append: Vec<String> = run_wfuzz(&thread_dir, &thread_target, &thread_port);
                thread_result.extend(append);
            }
        }));
    }

    for handle in wfuzz_handles {
        handle.join().unwrap();
    }

    let filename = format!("{}/files_{}:{}", &ip_address, &target, &port);
    let create = create_output_file(username, &filename);
    match create {
        Ok(_) => (),
        Err(err) => println!("{}", err)
    }
    let file_handle = OpenOptions::new()
                                  .create(true)
                                  .append(true)
                                  .open(&filename);

    match file_handle {
        Ok(file_handle) => {
            // Get the end results from wfuzz
            let wfuzz_result = wfuzz_result.lock().unwrap();
            // Write the results line by line to the file
            for entry in wfuzz_result.iter() {
                let write = writeln!(&file_handle, "{}", entry);
                match write {
                    Ok(_) => continue,
                    Err(err) => println!("Failed to write \"{}\" to {}: {}", entry, filename, err)
                }
            }
        },
        Err(err) => println!("Problem obtaining handle to {}: {}", filename, err),
    }

}


fn run_wfuzz(dir: &str, target: &str, port: &str) -> Vec<String> {
    // Format a string to pass to wfuzz
    let wfuzz_arg = format!("http://{}:{}{}/FUZZ", target, port, dir);
    // Wfuzz + a million arguments
    let wfuzz = Command::new("wfuzz")
                        .arg("-w")
                        .arg("/usr/share/wordlists/seclists/raft-medium-files.txt")
                        .arg("-t")
                        .arg("20")
                        .arg("--hc")
                        .arg("301,302,404")
                        .arg("-o")
                        .arg("raw")
                        .arg(wfuzz_arg)
                        .output();

    match wfuzz {
        Ok(wfuzz) => {
            // Grab the output and convert it to a string
            let wfuzz = String::from_utf8(wfuzz.stdout).unwrap();
            // Remove whitespace
            let wfuzz = wfuzz.trim();
            // Split it by newlines and allow it to be mutable
            let wfuzz: Vec<String> = wfuzz.split("\n")
                                          .map(|s| s.trim().to_string())
                                          .collect();

            // Some of this is garbage banner stuff, so filter that out
            let header_elements_end = 5;
            let footer_elements_begin = wfuzz.len() - 4;
            // The first and third banner entries are useful, grab those
            let mut wfuzz_out = vec![wfuzz[0].clone(), wfuzz[2].clone()];
            // Only include the other parts that are not part of the banner
            for found in wfuzz[header_elements_end..footer_elements_begin].iter() {
                wfuzz_out.push(String::from(found));
            }

            println!("\tCompleted wfuzz scan for http://{}:{}{}/", &target, &port, &dir);
            // Return filtered parts
            return wfuzz_out
        },
        Err(err) => {
            println!("\tFailed to run wfuzz scan for http://{}:{}{}/: {}", &target, &port, &dir, err);

            return vec![]
        }
    }

}
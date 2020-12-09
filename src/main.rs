/*
 Author: Kevin Conley <kmancxc@gmail.com>
 GitHub: https://github.com/kmanc/
*/

use std::env;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};
use std::net::IpAddr;
use std::process::{self, Command};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Debug)]
struct TargetMachine {
    ip: IpAddr,
    hostname: Option<String>,
}


struct ServicePorts {
    ftp: Vec<String>,
    http: Vec<String>,
    https: Vec<String>,
}


fn main() {
    // Make sure the script is run as sudo, exit if not
    sudo_check();

    // Collect the command line args
    let args: Vec<String> = env::args().collect();
    // Get the user entered IP address(es) and optionally hostname(s)
    let targets = get_targets_from_command_line(&args);
    println!("Targets: {:?}", targets);
    // Just take the first IP address for now
    let ip_address = &targets[0].ip.to_string();
    // Just take the first hostname if it was entered
    let hostname = &String::from(targets[0].hostname.as_deref().unwrap_or("None"));

    // Ping the machine to make sure it is alive
    println!("Verifying connectivity to {}", ip_address);
    ping_check(&ip_address);
    println!("\tConnectivity confirmed!");

    // Get the user associated with the active shell session for file permissions later
    let username = capture_username();

    // Create directory for storing things in
    println!("Creating directory \"{}\" to store resulting files in", ip_address);
    create_directory(&username, &ip_address);

    // Create a vector for threads so we can keep track of them and join on them all at the end
    let mut threads = Vec::new();

    // Spawn thread for nmap scan on all tcp ports
    println!("Kicking off thread for scanning all TCP ports");
    threads.push(thread::spawn({
        // Clone variables so the thread can use them without borrowing/ttl issues
        let (tcp_thread_username, tcp_thread_ip) = (username.clone(), ip_address.clone());
        move|| {
            run_tcp_all_nmap(&tcp_thread_username, &tcp_thread_ip);
        }
    }));

    // Spawn thread for showmount scan
    println!("Kicking off thread for listing NFS shares");
    threads.push(thread::spawn({
        // Clone variables so the thread can use them without borrowing/ttl issues
        let (showmount_thread_username, showmount_thread_ip) = (username.clone(), ip_address.clone());
        move|| {
            run_showmount(&showmount_thread_username, &showmount_thread_ip);
        }
    }));

    // If the user entered a hostname, add it to /etc/hosts
    if hostname != "None" {
    //if !hostname.is_empty() {
        // Create variable for filename "/etc/hosts" because we'll use it in a bunch of places
        let filename = "/etc/hosts";
        // Create a pattern to see if the IP/hostname pair is in /etc/hosts
        let grep_pattern = format!("({})\\s({})$", ip_address, hostname);
        // Run the grep command
        let grep = Command::new("grep")
                       .arg("-E")
                       .arg(grep_pattern)
                       .arg(filename)
                       .output()
                       .expect("Failed to run the grep command");
        // Capture the grep output and convert it to a string
        let grep = String::from_utf8(grep.stdout).unwrap();

        // If grep is empty, then the pair wasn't in /etc/hosts, so add it
        if grep.is_empty() {
            // Obtain a file handle with appending write to /etc/hosts
            let file_handle = OpenOptions::new()
                                          .append(true)
                                          .open(filename);
            match file_handle {
                Ok(file_handle) => {
                    // Let the user know you are writing the IP/hostname pair to /etc/hosts
                    println!("Adding \"{} {}\" to /etc/hosts and preparing additional discovery", &ip_address, &hostname);
                    // Write the IP/hostname pair to /etc/hosts
                    writeln!(&file_handle, "{} {}", &ip_address, &hostname).expect("Could not write to /etc/hosts");
                    println!("\t/etc/hosts updated");
                },
                Err(err) => println!("Problem obtaining handle to {}: {}", filename, err),
            }
        }
    }

    // Run a basic nmap scan with service discovery
    println!("Running \"nmap -sV {}\" for basic target information", ip_address);
    let parsed_nmap = run_basic_nmap(&username, &ip_address);

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
                let (nikto_thread_username, nikto_thread_ip, nikto_thread_host, nikto_thread_port) = (username.clone(), ip_address.clone(), web_host.clone(), port.clone());
                move || {
                    run_nikto(&nikto_thread_username, &nikto_thread_ip, &nikto_thread_host, &nikto_thread_port);
                }
            }));
            println!("Kicking off thread for gobuster/wfuzz scans on {}:{}", &web_host, &port);
            threads.push(thread::spawn({
                // Clone variables so the thread can use them without borrowing/ttl issues
                let (web_thread_username, web_thread_ip, web_thread_host, web_thread_port) = (username.clone(), ip_address.clone(), web_host.clone(), port.clone());
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

    io::stdout().flush().unwrap();
}


fn sudo_check() {
    // Run "id -u"
    let sudo = Command::new("id")
               .arg("-u")
               .output()
               .expect("Could not run sudo check");
    // Capture output as a vector of ascii bytes
    let sudo = sudo.stdout;
    // Exit if result was not [48, 10] (ie ascii "0\n")
    // And alert the user that more perms are needed
    if !(sudo[0] == 48 && sudo[1] == 10) {
        println!("EXITING - I need elevated privileges. Please run me with \"sudo\"");
        process::exit(0x0001);
    }
}


fn get_targets_from_command_line(args: &[String]) -> Vec<TargetMachine> {
    // Start a vector of targets
    let mut targets: Vec<TargetMachine> = vec![];
    // Make a "last seen" variable for look-back capability
    let mut last: Option<IpAddr> = None;
    // Iterate over the arguments we were given (skipping the first because it will be the executable name)
    for arg in args[1..].iter() {
        // Trim the arg in case of whitespace nonsense
        let arg = arg.trim();
        // Attempt to parse the argument as an IP address
        let ip = arg.parse::<IpAddr>();
        // Match on the IP address, which is either a valid IP or an error
        match ip {
            // If the IP address is valid
            Ok(ip) => {
                // If last is None
                if last == None {
                    // Set last to the IP address
                    last = Some(ip);
                }
                // Otherwise if last is not None
                else if last != None {
                    // Add a target machine to the list with last as its IP address and None as its hostname
                    targets.push(TargetMachine{
                        ip: last.unwrap(),
                        hostname: None,
                    });
                    // Then set last as the IP address
                    last = Some(ip);
                }
            }
            // If the IP address is an error
            Err(_) => {
                // If last is None
                if last == None {
                    // Exit because either the person typo'd an IP address or entered two straight hostnames
                    println!("EXITING - The argument \"{}\" is not valid. Please enter IP addresses (each optionally followed by one associated hostname)", arg);
                    process::exit(1);
                }
                // Otherwise if last is not None
                else if last != None {
                    // Add a target machine to the list with last as its IP address and the argument as its hostname
                    targets.push(TargetMachine{
                        ip: last.unwrap(),
                        hostname: Some(String::from(arg)),
                    });
                    // Set last to None
                    last = None;
                }
            }
        }
    }

    // If the last argument supplied was an IP address it needs to be added to the list with no hostname
    if last != None {
        targets.push(TargetMachine{
                ip: last.unwrap(),
                hostname: None,
        });
    }

    // If there hasn't been a single target parsed, exit because we have nothing to do
    if targets.len() == 0 {
        println!("EXITING - Please provide at least one valid IP address as a target");
        process::exit(1);
    }

    // Return the arguments struct, containing the IP address and hostname vectors
    targets
}


fn ping_check(target: &str) {
    // Ping the target 4 times
    let ping = Command::new("ping")
                       .arg("-c")
                       .arg("4")
                       .arg(target)
                       .output()
                       .expect("Failed to run the ping command");

    // Capture the ping output and convert it to a string
    let ping = String::from_utf8(ping.stdout).unwrap();

    // Exit if all 4 packets were lost
    if ping.contains("100.0% packet loss") {
        println!("EXITING - 4 / 4 attempts to ping {} failed", target);
        process::exit(1);
    }
}

fn capture_username() -> String {
    // Run "who -m | awk '{print $1}'"
    let who = Command::new("who")
              .output()
              .expect("Could not check who the current user is");

    // Capture output and convert it to a string
    let who = String::from_utf8(who.stdout).unwrap();
    // Convert to a vector by splitting on spaces
    let who: Vec<&str> = who.split(" ").collect();

    // Return the first element (username) as string
    String::from(who[0])
}


fn create_directory(username: &str, directory: &str) {
    // Prep an error string in case file creation fails for some reason
    let create_error_message = format!("Failed to create new directory {}", directory);

    // Create a file as the provided user with the desired name
    Command::new("sudo")
        .arg("-u")
        .arg(username)
        .arg("mkdir")
        .arg(directory)
        .output()
        .expect(&create_error_message);
}


fn create_output_file(username: &str, filename: &String) {
    // Prep an error string in case file creation fails for some reason
    let create_error_message = format!("Failed to create file {}", filename);

    // Create a file as the provided user with the desired name
    Command::new("sudo")
        .arg("-u")
        .arg(username)
        .arg("touch")
        .arg(filename)
        .output()
        .expect(&create_error_message);
}


fn run_basic_nmap(username: &str, ip_address: &str) -> ServicePorts {
    // Format filename for use in the nmap function and parser
    let filename = format!("{}/nmap_basic", ip_address);
    // Create the basic nmap scan file, which will be used to determine what else to run
    create_output_file(username, &filename);

    // Obtain a file handle with write permissions
    let file_handle = OpenOptions::new()
                                  .write(true)
                                  .open(&filename);

    match file_handle {
        Ok(file_handle) => {
            // Run an nmap command with -sV and -O flags, and use the file handle for stdout
            Command::new("nmap")
                    .arg("-sV")
                    .arg(ip_address)
                    .stdout(file_handle)
                    .output()
                    .expect("\"nmap -sV\" command failed to run");
        },
        Err(err) => println!("Problem obtaining handle to {}: {}", filename, err),
    }

    println!("\tBasic nmap scan complete!");

    println!("Reading results from \"nmap -sV {}\" to determine next steps", ip_address);

    // Set an empty vector of ftp ports
    let mut ftp: Vec<String> = vec![];
    // Set an empty vector of http ports
    let mut http: Vec<String> = vec![];
    // Set an empty vector of https ports
    let mut https: Vec<String> = vec![];

    // Obtain a file handle with read permissions
    let file_handle = OpenOptions::new()
                                  .read(true)
                                  .open(&filename);

    match file_handle {
        Ok(file_handle) => {
            // Get the file contents into a buffer
            let buffer = BufReader::new(file_handle);
            // Read the buffer line by line
            for line in buffer.lines() {
                // Skip the line if there is an error iterating over it
                match line {
                    Ok(line) => {
                        // Split the line into a vector by spaces
                        let line: Vec<&str> = line.split(" ").collect();
                        if line.contains(&"open") && line.contains(&"ftp") {
                            // If the line indicates ftp is open, get the port and add it to the ftp vector
                            let port = get_port_from_line(line);
                            ftp.push(port);
                        } else if line.contains(&"open") && line.contains(&"http") {
                            // If the line indicates http is open, get the port and add it to the http vector
                            let port = get_port_from_line(line);
                            http.push(port);
                        } else if line.contains(&"open") && line.contains(&"ssl/http") {
                            // If the line indicates https is open, get the port and add it to the https vector
                            let port = get_port_from_line(line);
                            https.push(port);
                        }
                    },
                    Err(_) => continue,
                };
            }
        },
        Err(err) => println!("Problem obtaining handle to {}: {}", filename, err),
    }

    // Return the vectors for all of the services we looked for
    ServicePorts { ftp, http, https }
}


fn get_port_from_line(line: Vec<&str>) -> String {
    // Convert the first element of the vector to a string
    let port = String::from(line[0]);
    // Split the first element at slashes
    let port: Vec<&str> = port.split("/").collect();

    // Return the first portion of the result as a string
    String::from(port[0])
}


fn run_tcp_all_nmap(username: &str, ip_address: &str) {
    let filename = format!("{}/nmap_all_tcp", ip_address);
    create_output_file(username, &filename);

    // Obtain a file handle with write permissions
    let file_handle = OpenOptions::new()
                                  .write(true)
                                  .open(&filename);

    match file_handle {
        Ok(file_handle) => {
            // Run an nmap command with -p-, and use the file handle for stdout
            Command::new("nmap")
                    .arg("-p-")
                    .arg(ip_address)
                    .stdout(file_handle)
                    .output()
                    .expect("\"nmap -p-\" command failed to run");
        },
        Err(err) => println!("Problem obtaining handle to {}: {}", filename, err),
    }

    println!("\tCompleted nmap scan for all TCP ports");
}


fn run_showmount(username: &str, ip_address: &str) {
    let filename = format!("{}/nfs_shares", ip_address);
    create_output_file(username, &filename);

    // Obtain a file handle with write permissions
    let file_handle = OpenOptions::new()
                                  .write(true)
                                  .open(&filename);

    match file_handle {
        Ok(file_handle) => {
            // Run the showmount command with -e, and use the file handle for stdout
            Command::new("showmount")
                    .arg("-e")
                    .arg(ip_address)
                    .stdout(file_handle)
                    .output()
                    .expect("\"showmount -e \" command failed to run");
        },
        Err(err) => println!("Problem obtaining handle to {}: {}", filename, err),
    }

    println!("\tCompleted scan for NFS shares");
}


fn run_nikto(username: &str, ip_address: &str, target: &str, port: &str) {
    let filename = format!("{}/nikto_{}:{}", &ip_address, &target, &port);
    let target = String::from(target);
    let port = String::from(port);
    create_output_file(username, &filename);

    println!("Starting a nikto scan on {}:{}", &target, &port);

    // Obtain a file handle with write permissions
    let file_handle = OpenOptions::new()
                                  .write(true)
                                  .open(&filename);

    match file_handle {
        Ok(file_handle) => {
            // Run the nikto command with a bunch of flags, and use the file handle for stdout
            Command::new("nikto")
                    .arg("-host")
                    .arg(&target)
                    .arg("-port")
                    .arg(&port)
                    .stdout(file_handle)
                    .output()
                    .expect("nikto command failed to run");
        },
        Err(err) => println!("Problem obtaining handle to {}: {}", filename, err),
    }

    println!("\tCompleted nikto scan on {}:{}", &target, &port);
}


fn run_gobuster_wfuzz(username: &str, ip_address: &str, target: &str, port: &str) {
    let filename = format!("{}/dirs_{}:{}", &ip_address, &target, &port);
    let target = String::from(target);
    let port = String::from(port);
    create_output_file(username, &filename);

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
                                   .output()
                                   .expect("gobuster command failed to run");

            println!("\tCompleted gobuster scan for {}:{}", &target, &port);

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
    create_output_file(username, &filename);
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
                writeln!(&file_handle, "{}", entry).expect("Error writing line to wfuzz file");
            }
        },
        Err(err) => println!("Problem obtaining handle to {}: {}", filename, err),
    }

}


fn run_wfuzz(dir: &str, target: &str, port: &str) -> Vec<String> {
    // Format a string to pass to wfuzz
    let wfuzz_arg = format!("http://{}:{}{}/FUZZ", target, port, dir);
    // Format a string in case of error
    let wfuzz_err = format!("Failed to run wfuzz on {} port {}'s {} directory", target, port, dir);
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
                        .output()
                        .expect(&wfuzz_err);

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
    wfuzz_out
}
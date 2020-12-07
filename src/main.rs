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


fn main(){
    // Make sure the script is run as sudo, exit if not
    sudo_check();

    // Collect the command line args
    let args: Vec<String> = env::args().collect();
    // Get the user entered IP address(es) and optionally hostname(s)
    let args = parse_args(&args);
    // Just take the first IP address for now
    let ip_address = &String::from("192.168.1.1");
    // Just take the first hostname if it was entered
    let hostname = &String::from("koins.cloud");

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
        let tcp_file = format!("{}/nmap_all_tcp", ip_address);
        move|| {
            run_tcp_all_nmap(&tcp_thread_username, &tcp_thread_ip, &tcp_file);
        }
    }));

    // Spawn thread for showmount scan
    println!("Kicking off thread for listing NFS shares");
    threads.push(thread::spawn({
        // Clone variables so the thread can use them without borrowing/ttl issues
        let (showmount_thread_username, showmount_thread_ip) = (username.clone(), ip_address.clone());
        let showmount_file = format!("{}/nfs_shares", ip_address);
        move|| {
            run_showmount(&showmount_thread_username, &showmount_thread_ip, &showmount_file);
        }
    }));

    // If the user entered a hostname, add it to /etc/hosts
    if !hostname.is_empty() {
        // Create a pattern to see if the IP/hostname pair is in /etc/hosts
        let grep_pattern = format!("({})\\s({})$", ip_address, hostname);
        // Run the grep command
        let grep = Command::new("grep")
                       .arg("-E")
                       .arg(grep_pattern)
                       .arg("/etc/hosts")
                       .output()
                       .expect("Failed to run the grep command");
        // Capture the grep output
        let grep = grep.stdout;
        // Convert it to a string
        let grep = String::from_utf8(grep).unwrap();

        // If grep is empty, then the pair wasn't in /etc/hosts, so add it
        if grep.is_empty() {
            // Obtain a file handle with appending write to /etc/hosts
            let file_handle = OpenOptions::new()
                                          .append(true)
                                          .open("/etc/hosts")
                                          .expect("Could obtain a handle to /etc/hosts");
            // Let the user know you are writing the IP/hostname pair to /etc/hosts
            println!("Adding \"{} {}\" to /etc/hosts and preparing additional discovery", &ip_address, &hostname);
            // Write the IP/hostname pair to /etc/hosts
            writeln!(&file_handle, "{} {}", &ip_address, &hostname).expect("Could not write to /etc/hosts");
            println!("\t/etc/hosts updated");
        }
    }

    // Run a basic nmap scan with service discovery and OS fingerprinting
    println!("Running \"nmap -sV -O {}\" for basic target information", ip_address);
    let basic_file = format!("{}/nmap_basic", ip_address);
    run_basic_nmap(&username, &ip_address, &basic_file);
    println!("\tBasic nmap scan complete!");

    println!("Reading results from \"nmap -sV {}\" to determine next steps", ip_address);
    let parsed_nmap = parse_basic_nmap(&basic_file);
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
    // Capture output as a vector
    let sudo = sudo.stdout;
    // Exit if result was not [48, 10] (ie ascii "0\n")
    // And alert the user that more perms are needed
    if !(sudo[0] == 48 && sudo[1] == 10) {
        println!("EXITING - I need elevated privileges. Please run me with \"sudo\"");
        process::exit(0x0001);
    }
}


fn parse_args(args: &[String]) -> Vec<TargetMachine> {
    // Exit early if no arguments were supplied
    if args.len() == 1 {
        println!("EXITING - Please provide at least one valid IP address as an argument");
        process::exit(1);
    }
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
        // If the argument is an IP address, but the variable last is set to None (as it is on first run)
        if !ip.is_err() && last == None {
            // Set last to the IP address
            last = Some(ip.unwrap());
        }
        // If the argument is an IP address and the variable last is not None
        else if !ip.is_err() && last != None {
            // Add a target machine to the list with last as its IP address and None as its hostname
            targets.push(TargetMachine{
                ip: last.unwrap(),
                hostname: None,
            });
            last = Some(ip.unwrap());
        }
        // If the argument is not an IP address and the variable last is not None
        else if ip.is_err() && last != None {
            // Add a target machine to the list with last as its IP address and the argument as its hostname
            targets.push(TargetMachine{
                ip: last.unwrap(),
                hostname: Some(String::from(arg)),
            });
            last = None;
        }
        // If the argument is not an IP address and the last variable is None
        else {
            // Exit because either the person typo'd an IP address or entered two straight hostnames
            println!("EXITING - The argument {} is not valid. Please enter IP addresses (optionally followed by associated hostnames)", arg);
            process::exit(1);
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
    // Capture the ping output
    let ping = ping.stdout;
    // Convert it to a string
    let ping = String::from_utf8(ping).unwrap();

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
    // Capture output as a vector
    let who = who.stdout;
    // Convert it to a string
    let who = String::from_utf8(who).unwrap();
    // Split it on the first space
    let who_result_vector: Vec<&str> = who.split(" ").collect();

    // Return username as string
    String::from(who_result_vector[0])
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
    let create_error_message = format!("Failed to create new file {}", filename);

    // Create a file as the provided user with the desired name
    Command::new("sudo")
        .arg("-u")
        .arg(username)
        .arg("touch")
        .arg(filename)
        .output()
        .expect(&create_error_message);
}


fn run_basic_nmap(username: &str, target: &str, filename: &String) {
    // Create the basic nmap scan file, which will be used to determine what else to run
    create_output_file(username, &filename);

    // Prep an error string in case the file handle can't be obtained
    let handle_error_message = format!("Failed to obtain handle to file {}", filename);

    // Obtain a file handle with write permissions
    let file_handle = OpenOptions::new()
                                  .write(true)
                                  .open(&filename)
                                  .expect(&handle_error_message);

    // Run an nmap command with -sV and -O flags, and use the file handle for stdout
    Command::new("nmap")
            .arg("-sV")
            .arg(target)
            .stdout(file_handle)
            .output()
            .expect("nmap command failed to run");
}


fn parse_basic_nmap(filename: &String) -> ServicePorts {
    // Set an empty vector of ftp ports
    let mut ftp: Vec<String> = vec![];
    // Set an empty vector of http ports
    let mut http: Vec<String> = vec![];
    // Set an empty vector of https ports
    let mut https: Vec<String> = vec![];

    // Prep an error string in case the file handle can't be obtained
    let handle_error_message = format!("Failed to obtain handle to file {}", filename);

    // Obtain a file handle with read permissions
    let file_handle = OpenOptions::new()
                                  .read(true)
                                  .open(&filename)
                                  .expect(&handle_error_message);

    // Get the file contents into a buffer
    let buffer = BufReader::new(file_handle);
    // Read the buffer line by line
    for (_, line) in buffer.lines().enumerate() {
        // Skip the line if there is an error iterating over it
        let line = match line {
            Ok(line) => line,
            Err(_) => continue,
        };
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


fn run_tcp_all_nmap(username: &str, target: &str, filename: &String) {
    create_output_file(username, &filename);

    // Prep an error string in case the file handle can't be obtained
    let handle_error_message = format!("Failed to obtain handle to file {}", filename);

    // Obtain a file handle with write permissions
    let file_handle = OpenOptions::new()
                                  .write(true)
                                  .open(&filename)
                                  .expect(&handle_error_message);

    // Run an nmap command with -p-, and use the file handle for stdout
    Command::new("nmap")
            .arg("-p-")
            .arg(target)
            .stdout(file_handle)
            .output()
            .expect("nmap command failed to run");

    println!("\tCompleted nmap scan for all TCP ports");
}


fn run_showmount(username: &str, target: &str, filename: &String) {
    create_output_file(username, &filename);

    // Prep an error string in case the file handle can't be obtained
    let handle_error_message = format!("Failed to obtain handle to file {}", filename);

    // Obtain a file handle with write permissions
    let file_handle = OpenOptions::new()
                                  .write(true)
                                  .open(&filename)
                                  .expect(&handle_error_message);

    // Run the showmount command with -e, and use the file handle for stdout
    Command::new("showmount")
            .arg("-e")
            .arg(target)
            .stdout(file_handle)
            .output()
            .expect("showmount command failed to run");

    println!("\tCompleted scan for NFS shares");
}

fn run_nikto(username: &str, ip_address: &str, target: &str, port: &str) {
    let filename = format!("{}/nikto_{}:{}", &ip_address, &target, &port);
    let target = String::from(target);
    let port = String::from(port);
    create_output_file(username, &filename);

    println!("Starting a nikto scan on {}:{}", &target, &port);

    // Prep an error string in case the file handle can't be obtained
    let handle_error_message = format!("Failed to obtain handle to file {}", filename);

    // Obtain a file handle with write permissions
    let file_handle = OpenOptions::new()
                                  .write(true)
                                  .open(&filename)
                                  .expect(&handle_error_message);

    // Run the showmount command with -e, and use the file handle for stdout
    Command::new("nikto")
            .arg("-host")
            .arg(&target)
            .arg("-port")
            .arg(&port)
            .stdout(file_handle)
            .output()
            .expect("nikto command failed to run");

    println!("\tCompleted nikto scan on {}:{}", &target, &port);
}


fn run_gobuster_wfuzz(username: &str, ip_address: &str, target: &str, port: &str) {
    let filename = format!("{}/dirs_{}:{}", &ip_address, &target, &port);
    let target = String::from(target);
    let port = String::from(port);
    create_output_file(username, &filename);

    println!("Starting gobuster directory scan on {}:{}", &target, &port);

    // Prep an error string in case the file handle can't be obtained
    let handle_error_message = format!("Failed to obtain handle to file {}", filename);

    // Obtain a file handle with write permissions
    let file_handle = OpenOptions::new()
                                  .write(true)
                                  .open(&filename)
                                  .expect(&handle_error_message);

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

    // Grab the stdout
    let gobuster = gobuster.stdout;
    // Convert it to a string
    let gobuster = String::from_utf8(gobuster).unwrap();
    // Remove whitespace
    let gobuster = gobuster.trim();
    // Split it by newlines and allow it to be mutable
    let mut gobuster: Vec<String> = gobuster.split("\n")
                                            .map(|s| s.trim().to_string())
                                            .collect();
    // Make sure at a bare minimum the empty string is in there so we will scan the root dir
    if !gobuster.iter().any(|i| i == "") {
        gobuster.push(String::from(""));
    }

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
                                  .open(filename)
                                  .expect("Could not obtain handle to wfuzz file");

    let wfuzz_result = wfuzz_result.lock().unwrap();
    for entry in wfuzz_result.iter() {
        writeln!(&file_handle, "{}", entry).expect("Error writing line to wfuzz file");
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

    // Grab the stdout
    let wfuzz = wfuzz.stdout;
    // Convert it to a string
    let wfuzz = String::from_utf8(wfuzz).unwrap();
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
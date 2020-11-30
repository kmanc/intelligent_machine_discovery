/*
 Author: Kevin Conley <kmancxc@gmail.com>
 GitHub: https://github.com/kmanc/
*/

use std::env;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::io::{BufRead, BufReader};
use std::net::{IpAddr};
use std::process;
use std::process::Command;
use std::thread;
use std::time::Duration;


struct Arguments {
    ips: Vec<String>,
    hostnames: Vec<String>,
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
    let ip_address = &args.ips[0];
    // Just take the first hostname if it was entered
    let hostname = &args.hostnames[0];

    // Ping the machine to make sure it is alive
    println!("Verifying connectivity to {}", ip_address);
    ping_check(&ip_address);
    println!("\tDone!");

    // Get the user associated with stdin for file permissions later
    let username = capture_username();

    // Create directory for storing things in
    println!("Creating directory \"{}\" to store resulting files in", ip_address);
    create_directory(&username, &ip_address);

    // Create a vector for threads so we can keep track of them and join on them all at the end
    let mut threads = Vec::new();

    // Spawn thread for nmap scan on all tcp ports
    println!("Kicking off thread for scanning all TCP ports");
    let (tcp_thread_username, tcp_thread_ip) = (username.clone(), ip_address.clone());
    let tcp_file = format!("{}/tcp_all_nmap", ip_address);
    threads.push(thread::spawn(move|| {
        run_tcp_all_nmap(&tcp_thread_username, &tcp_thread_ip, &tcp_file);
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
            let mut file_handle = OpenOptions::new()
                                              .append(true)
                                              .open("/etc/hosts")
                                              .expect("Could obtain a handle to /etc/hosts");
            // Let the user know you are writing the IP/hostname pair to /etc/hosts
            println!("Adding \"{} {}\" to /etc/hosts and running additional discovery", &ip_address, &hostname);
            // Write the IP/hostname pair to /etc/hosts
            writeln!(&file_handle, "{} {}", &ip_address, &hostname);
            println!("\tDone!");
        }
    }

    // Run a basic nmap scan with service discovery and OS fingerprinting
    println!("Running \"nmap -sV -O {}\" for basic target information", ip_address);
    ///*
    //    UNCOMMENT THIS WHEN YOURE READY BUT FOR THE TIME BEING THIS SAVES ENERGY
    let basic_file = format!("{}/basic_nmap", ip_address);
    run_basic_nmap(&username, &ip_address, &basic_file);
    //*/
    println!("\tDone!");

    println!("Reading results from \"nmap -sV -O {}\" to determine next steps", ip_address);
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
    println!("\tDone!");

    threads.push(thread::spawn(|| {
        webpage_scanning();
    }));


    // Wait for all outstanding threads to finish
    for thread in threads {
        thread.join().unwrap();
    }
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


fn parse_args(args: &[String]) -> Arguments {
    // Exit early if no arguments were supplied
    if args.len() == 1 {
        println!("EXITING - Please provide at least one valid IP address as an argument");
        process::exit(1);
    }
    // Assume until we're told otherwise that the first arguments are IP addresses
    let mut is_ip = true;
    // Get the name of the executable we ran so we don't parse it later
    let executable = &args[0];
    // Set a trigger to differentiate between IPs and hostnames
    let flag = &"-h";
    // Set an empty vector of IPs
    let mut ips: Vec<String> = vec![];
    // Set an empty vector of hostnames
    let mut hostnames: Vec<String> = vec![];
    // Iterate over the arguments we were given
    for arg in args.iter() {
        // Skip it completely if it is the executable name
        if arg == executable {
            continue
        }
        // If it is "-h", recognize that we will now be parsing hostnames, then skip it
        if arg == flag {
            is_ip = false;
            continue
        }
        if is_ip {
            // If it's supposed to be an IP address, verify it and add to the ip vector or exit
            let ip = arg.trim();
            let validate = ip.parse::<IpAddr>();
            if validate.is_err() {
                println!("EXITING - {} is not a valid IP address", ip);
                process::exit(1);
            }
            ips.push(String::from(ip));
        } else {
            // If it's supposed to be a hostname, add it to the hostname vector
            let hostname = arg.trim();
            hostnames.push(String::from(hostname));
        }
    }

    // If there hasn't been an IP address parsed, exit because we have no target
    if ips.len() == 0 {
        println!("EXITING - Please provide at least one valid IP address");
        process::exit(1);
    }

    // Return the arguments struct, containing the IP address and hostname vectors
    Arguments { ips, hostnames }
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
            .arg("-O")
            .arg(target)
            .stdout(file_handle)
            .output()
            .expect("ls command failed to start");
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

    // Run an nmap command with -sV and -O flags, and use the file handle for stdout
    Command::new("nmap")
            .arg("-p-")
            .arg(target)
            .stdout(file_handle)
            .output()
            .expect("ls command failed to start");
    println!("TCP all done");
}


fn webpage_scanning() {
    let filename = "blah.txt";
    let handle_error_message = format!("Failed to obtain handle to file {}", filename);

    let file_handle = OpenOptions::new()
                                   .write(true)
                                   .open(&filename)
                                   .expect(&handle_error_message);

    Command::new("ls")
            .stdout(file_handle)
            .output()
            .expect("ls command failed to start");
    println!("Web stuffs");
}
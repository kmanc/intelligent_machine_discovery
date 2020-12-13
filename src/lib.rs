use std::error::Error;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::net::IpAddr;
use std::process::{self, Command};

#[derive(Debug)]
pub struct Config {
    pub targets: Vec<TargetMachine>,
    pub username: String,
}

#[derive(Debug)]
pub struct TargetMachine {
    pub ip: IpAddr,
    pub hostname: Option<String>,
}

pub struct ServicePorts {
    pub ftp: Vec<String>,
    pub http: Vec<String>,
    pub https: Vec<String>,
}

impl Config {
    pub fn new(args: &[String]) -> Result<Config, Box<dyn Error>> {
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
                        // Return an error because either the person typo'd an IP address or entered two straight hostnames
                        return Err(format!("The argument \"{}\" is not valid. Please enter IP addresses (each optionally followed by one associated hostname)", arg).into());
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
            return Err("Please provide at least one valid IP address as a target".into());
        }

        // Get the user associated with the active shell session for folder and file permissions later or use root if we fail
        let username = capture_username();
        let username = match username {
            Ok(username) => username,
            Err(e) => {
                println!("Using \"root\" for file permissions because of error: {}", e);
                String::from("root")
            }
        };

        // Return the arguments struct, containing the IP address and hostname vectors
        Ok(Config{ targets, username })
    }

    pub fn create_dir(&self, dir_name: &str) -> Result<(), Box<dyn Error>> {
    // Create a file as the provided user with the desired name
    Command::new("sudo")
            .arg("-u")
            .arg(&self.username)
            .arg("mkdir")
            .arg(dir_name)
            .output()?;

    Ok(())
    }
}


impl TargetMachine {
    pub fn add_to_hosts(&self) -> Result<(), Box<dyn Error>>{
        // Create variable for filename "/etc/hosts" because we'll use it in a bunch of places
        let filename = "/etc/hosts";
        // Create a pattern to see if the IP/hostname pair is in /etc/hosts
        let grep_pattern = format!("({})\\s({})$", self.ip, self.hostname.as_deref().unwrap());
        // Run the grep command
        let grep = Command::new("grep")
                       .arg("-E")
                       .arg(grep_pattern)
                       .arg(&filename)
                       .output()?;

        // Capture the grep output and convert it to a string if it ran
        let grep= String::from_utf8(grep.stdout).unwrap();

        // If grep is empty, then the pair wasn't in /etc/hosts, so add it
        if grep.is_empty() {
            // Obtain a file handle with appending write to /etc/hosts
            let file_handle = OpenOptions::new()
                                          .append(true)
                                          .open(&filename)?;

            // Let the user know you are writing the IP/hostname pair to /etc/hosts
            println!("Adding \"{} {}\" to /etc/hosts and preparing additional discovery", self.ip, self.hostname.as_deref().unwrap());
            // Write the IP/hostname pair to /etc/hosts
            writeln!(&file_handle, "{} {}", self.ip, self.hostname.as_deref().unwrap())?;

            println!("\t/etc/hosts updated");
        }

        Ok(())
    }


    pub fn check_connection(&self) -> Result<(), Box<dyn Error>> {
        // Ping the target 4 times
        let ping = Command::new("ping")
                           .arg("-c")
                           .arg("4")
                           .arg(self.ip.to_string())
                           .output()?;

        let ping = String::from_utf8(ping.stdout).unwrap();

        // Exit if all 4 packets were lost
        if ping.contains("100.0% packet loss") {
            return Err(format!("4 / 4 attempts to ping \"{}\" failed, please check connectivity", self.ip).into())
        }

        Ok(())
    }


    fn run_nikto(&self, username: &str, target: &str, port: &str) -> Result<(), Box<dyn Error>> {
        let filename = format!("{}/nikto_{}:{}", &self.ip, &target, &port);
        let target = String::from(target);
        let port = String::from(port);
        create_output_file(username, &filename)?;

        println!("Starting a nikto scan on {}:{}", &target, &port);

        // Obtain a file handle with write permissions
        let file_handle = OpenOptions::new()
                                      .write(true)
                                      .open(&filename)?;

        // Run the nikto command with a bunch of flags, and use the file handle for stdout
        Command::new("nikto")
                .arg("-host")
                .arg(&target)
                .arg("-port")
                .arg(&port)
                .stdout(file_handle)
                .output()?;

        println!("\tCompleted nikto scan on {}:{}", &target, &port);
        Ok(())
    }


    pub fn nmap_scan_all_ports(&self, username: &str) -> Result<(), Box<dyn Error>> {
        let filename = format!("{}/nmap_all_tcp", self.ip);
        create_output_file(username, &filename)?;

        // Obtain a file handle with write permissions
        let file_handle = OpenOptions::new()
                                      .write(true)
                                      .open(&filename)?;

        // Run an nmap command with -p-, and use the file handle for stdout
        Command::new("nmap")
                .arg("-p-")
                .arg(self.ip.to_string())
                .stdout(file_handle)
                .output()?;

        Ok(())
    }


    pub fn nmap_scan_basic(&self, username: &str) -> Result<ServicePorts, Box<dyn Error>> {
        // Format filename for use in the nmap function and parser
        let filename = format!("{}/nmap_basic", self.ip);
        // Create the basic nmap scan file, which will be used to determine what else to run
        create_output_file(username, &filename)?;

        // Set an empty vector of ftp ports
        let mut ftp: Vec<String> = vec![];
        // Set an empty vector of http ports
        let mut http: Vec<String> = vec![];
        // Set an empty vector of https ports
        let mut https: Vec<String> = vec![];

        // Obtain a file handle with write permissions
        let file_handle = OpenOptions::new()
                                      .write(true)
                                      .open(&filename)?;

        // Run an nmap command with -sV flags, and use the file handle for stdout
        let nmap = Command::new("nmap")
                           .arg("-sV")
                           .arg(self.ip.to_string())
                           .stdout(file_handle)
                           .output()?;

        // Grab the output and convert it to a string
        let nmap = String::from_utf8(nmap.stdout).unwrap();
        // Remove whitespace
        let nmap = nmap.trim();
        // Convert it to a vector by splitting on newlines
        let nmap: Vec<String> = nmap.split("\n")
                                    .map(|s| s.trim().to_string())
                                    .collect();

        println!("Reading results from \"nmap -sV {}\" to determine next steps", self.ip);

        for line in nmap.iter() {
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
        Ok(ServicePorts { ftp, http, https })
    }

    pub fn showmount_scan(&self, username: &str) -> Result<(), Box<dyn Error>> {
        let filename = format!("{}/nfs_shares", self.ip);
        create_output_file = (username, &filename)?;

        // Obtain a file handle with write permissions
        let file_handle = OpenOptions::new()
                                      .write(true)
                                      .open(&filename)?;

        // Run the showmount command with -e, and use the file handle for stdout
        let showmount = Command::new("showmount")
                                .arg("-e")
                                .arg(self.ip.to_string())
                                .stdout(file_handle)
                                .output()?;

        println!("\tCompleted scan for NFS shares");
        Ok(())
    }
}


pub fn capture_username() -> Result<String, Box<dyn Error>> {
    // Run "who"
    let who = Command::new("who").output()?;

    // Capture output and convert it to a string
    let who = String::from_utf8(who.stdout).unwrap();
    // Convert to a vector by splitting on spaces
    let who: Vec<&str> = who.split(" ").collect();

    // Return the first element (username) as string
    Ok(String::from(who[0]))
}


fn create_output_file(username: &str, filename: &String) -> Result<(), Box<dyn Error>> {

    // Create a file as the provided user with the desired name
    Command::new("sudo")
            .arg("-u")
            .arg(username)
            .arg("touch")
            .arg(filename)
            .output()?;

    Ok(())
}

fn get_port_from_line(line: Vec<&str>) -> String {
    // Convert the first element of the vector to a string
    let port = String::from(line[0]);
    // Split the first element at slashes
    let port: Vec<&str> = port.split("/").collect();

    // Return the first portion of the result as a string
    String::from(port[0])
}


pub fn sudo_check() -> Result<(), Box<dyn Error>> {
    // Run "id -u" and propagate the error if there is one
    let sudo = Command::new("id")
                               .arg("-u")
                               .output()?;

    // Capture output as a vector of ascii bytes
    let sudo = sudo.stdout;
    // Return an error if result was not [48, 10] (ie ascii "0\n")
    if !(sudo[0] == 48 && sudo[1] == 10) {
        return Err("\"imd\" needs elevated privileges - please run with \"sudo\"".into())
    }

    // Return Ok result if we are id 0
    Ok(())
}
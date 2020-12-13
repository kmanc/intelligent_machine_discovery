use std::error::Error;
use std::fs::OpenOptions;
use std::net::IpAddr;
use std::process::{self, Command};

#[derive(Debug)]
pub struct Arguments {
    pub targets: Vec<TargetMachine>,
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


pub fn basic_nmap(username: &str, ip_address: &str) -> Result<ServicePorts, Box<dyn Error>> {
    // Format filename for use in the nmap function and parser
    let filename = format!("{}/nmap_basic", ip_address);
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
                       .arg(ip_address)
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

    println!("Reading results from \"nmap -sV {}\" to determine next steps", ip_address);

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


pub fn parse_command_line(args: Vec<String>) -> Result<Arguments, Box<dyn Error>> {
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

    // Return the arguments struct, containing the IP address and hostname vectors
    Ok(Arguments{ targets })
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
use std::collections::HashMap;
use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::IpAddr;
use std::process::Command;

pub struct Config {
    targets: Vec<TargetMachine>,
    username: String,
}

pub struct TargetMachine {
    ip: IpAddr,
    hostname: Option<String>,
    services: Option<HashMap<String, Vec<String>>>
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
                        targets.push(TargetMachine::new(last.unwrap(), None, None));
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
                        targets.push(TargetMachine::new(last.unwrap(), Some(arg.to_owned()), None));
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
                    services: None
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
                eprintln!("Using \"root\" for file permissions because of error: {}", e);
                String::from("root")
            }
        };

        // Return the arguments struct, containing the IP address and hostname vectors
        Ok(Config{ targets, username })
    }


    pub fn targets(&self) -> &Vec<TargetMachine> {
        &self.targets
    }


    pub fn username(&self) -> &String {
        &self.username
    }
}


impl TargetMachine {
    pub fn add_to_hosts(&self) -> Result<(), Box<dyn Error>> {
        println!("Checking /etc/hosts file for {} {}", self.ip, self.hostname.as_deref().unwrap());
        // Create variable for filename "/etc/hosts" because we'll use it in a bunch of places
        let filename = "/etc/hosts";
        // Create a pattern to see if the IP/hostname pair is in /etc/hosts
        let grep_pattern = format!("({})\\s({})$", self.ip, self.hostname.as_deref().unwrap());
        // Grep /etc/hosts for the IP/hostname pair
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

            // Write the IP/hostname pair to /etc/hosts
            writeln!(&file_handle, "{} {}", self.ip, self.hostname.as_deref().unwrap())?;

            println!("\t/etc/hosts updated");
        } else {
            println!("\t/etc/hosts already contains {} {}", self.ip, self.hostname.as_deref().unwrap());
        }

        Ok(())
    }


    pub fn bulk_gobuster(&self, username: &str, protocol: &str, target: &str, ports: &Vec<String>) -> Result<Vec<String>, Box<dyn Error>> {
        let mut web_dirs: Vec<String> = vec![];
        for port in ports.iter() {
            match &self.gobuster_scan(username, protocol, target, port) {
                Ok(gobuster) => {
                    for dir in gobuster.iter() {
                        let dir: Vec<&str> = dir.split(" ").collect();
                        let finding = format!("{}://{}:{}{}", protocol, target, port, dir[0]);
                        web_dirs.push(finding)
                    }
                },
                Err(e) => eprintln!("{}", e)
            }
        }

        Ok(web_dirs)
    }


    pub fn bulk_nikto(&self, username: &str, protocol: &str, target: &str, ports: &Vec<String>) -> Result<(), Box<dyn Error>> {
        for port in ports.iter() {
            &self.nikto_scan(username, protocol, target, port)?;
        }

        Ok(())
    }


    pub fn bulk_wfuzz(&self, username: &str, protocol: &str, targets: Vec<String>) -> Result<(), Box<dyn Error>> {
        let filename = format!("{}/wfuzz_{}", &self.ip, protocol);
        create_output_file(username, &filename)?;

        // Obtain a file handle with write permissions
        let file_handle = OpenOptions::new()
                                      .write(true)
                                      .open(&filename)?;

        let mut web_files: Vec<String> = vec![];
        for target in targets.iter() {
            match &self.wfuzz_scan(target) {
                Ok(wfuzz) => {
                    for file in wfuzz.iter() {
                        web_files.push(file.to_string());
                    }
                },
                Err(e) => eprintln!("{}", e)
            }
        }

        writeln!(&file_handle, "{}", web_files.join("\n"))?;

        Ok(())
    }


    pub fn check_connection(&self) -> Result<(), Box<dyn Error>> {
        println!("Verifying connectivity to {}", self.ip.to_string());
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


    pub fn hostname(&self) -> Option<&String> {
        match &self.hostname {
            Some(hostname) => Some(hostname),
            None => None
        }
    }


    pub fn gobuster_scan(&self, username: &str, protocol: &str, target: &str, port: &str) -> Result<Vec<String>, Box<dyn Error>> {
        let gobuster_arg = format!("{}://{}:{}", protocol, target, port);
        println!("Starting gobuster directory scan on {}", &gobuster_arg);
        let filename = format!("{}/dirs_{}_port_{}", &self.ip, target, port);
        create_output_file(username, &filename)?;

        // Obtain a file handle with write permissions
        let file_handle = OpenOptions::new()
                                      .write(true)
                                      .open(&filename)?;

        // Run gobuster with a slew of flags
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
                               .output()?;

        // Grab the output and convert it to a string
        let gobuster = String::from_utf8(gobuster.stdout)?;
        // Write the output to a file for the user in a way that allows for later use
        writeln!(&file_handle, "{}", &gobuster)?;
        // Convert it to a vector by splitting on newlines and allow it to be mutable - also trim each line
        let mut gobuster: Vec<String> = gobuster.split("\n")
                                              .map(|s| s.trim().to_string())
                                              .collect();
        // Make sure at a bare minimum the empty string is in there so we will scan the root dir
        if !gobuster.iter().any(|i| i == "") {
            gobuster.push(String::from(""));
        }

        println!("\tCompleted gobuster scan for {}", &gobuster_arg);

        // Return gobuster results
        Ok(gobuster)
    }


    pub fn ip(&self) -> &IpAddr {
        &self.ip
    }


    pub fn new(ip: IpAddr, hostname: Option<String>, services: Option<HashMap<String, Vec<String>>>) -> TargetMachine {
        TargetMachine{
            ip,
            hostname,
            services
        }
    }


    pub fn nikto_scan(&self, username: &str, protocol: &str, target: &str, port: &str) -> Result<(), Box<dyn Error>> {
        let nikto_arg = format!("{}://{}:{}", protocol, target, port);
        println!("Starting a nikto scan on {}", nikto_arg);
        let filename = format!("{}/nikto_{}_port_{}", &self.ip, target, port);
        create_output_file(username, &filename)?;

        // Obtain a file handle with write permissions
        let file_handle = OpenOptions::new()
                                      .write(true)
                                      .open(filename)?;

        // Run the nikto command with a bunch of flags, and use the file handle for stdout
        Command::new("nikto")
                .arg("-host")
                .arg(&nikto_arg)
                .stdout(file_handle)
                .output()?;

        println!("\tCompleted nikto scan on {}", nikto_arg);
        Ok(())
    }


    pub fn nmap_scan_all_tcp(&self, username: &str) -> Result<(), Box<dyn Error>> {
        println!("Running \"nmap -p- {}\" for information on all TCP ports", self.ip);
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


    pub fn nmap_scan_common(&self, username: &str) -> Result<Option<HashMap<String, Vec<String>>>, Box<dyn Error>> {
        println!("Running \"nmap -sV {}\" (plus a few NSE scripts) for information on common ports", self.ip);
        // Format filename for use in the nmap function and parser
        let filename = format!("{}/nmap_common", self.ip);
        // Create the common port nmap scan file, which will be used to determine what else to run
        create_output_file(username, &filename)?;

        let mut service_hashmap: HashMap<String, Vec<String>> = HashMap::new();

        // Obtain a file handle with write permissions
        let file_handle = OpenOptions::new()
                                      .write(true)
                                      .open(&filename)?;

        // Run an nmap command with -A flag, and use the file handle for stdout
        let nmap = Command::new("nmap")
                           .arg("-sV")
                           .arg("--script")
                           .arg("finger")
                           .arg("--script")
                           .arg("http-robots.txt")
                           .arg("--script")
                           .arg("http-title")
                           .arg("--script")
                           .arg("ssl-cert")
                           .arg(self.ip.to_string())
                           .output()?;

        // Grab the output and convert it to a string
        let nmap = String::from_utf8(nmap.stdout).unwrap();
        // Write the output to a file for the user in a way that allows for later use
        writeln!(&file_handle, "{}", &nmap)?;
        // Convert it to a vector by splitting on newlines - also trim each line
        let nmap: Vec<String> = nmap.split("\n")
                                    .map(|s| s.trim().to_string())
                                    .collect();

        println!("\tCompleted nmap scan on common ports");
        println!("Reading results from \"nmap -sV {}\" to determine next steps", self.ip);

        // We put spaces in front of each service to make sure we don't double count http and ssl/http later
        let services = vec!["ftp", "ssh", "http", "ssl/http"];

        for service in services {
            for line in nmap.iter() {
                if line.starts_with("|") {
                    continue;
                }
                let line: Vec<&str> = line.split(" ").collect();
                if line.contains(&"open") && line.contains(&service) {
                    let port = get_port_from_line(line);
                    service_hashmap.entry(service.trim().to_string()).or_default().push(port);
                }
            }
        }
        println!("\tCompleted planning next steps based on nmap scan");

        // Return the map of services and ports we found
        Ok(Some(service_hashmap))
    }


    pub fn services(&self) -> Option<&HashMap<String, Vec<String>>> {
        match &self.services {
            Some(services) => Some(services),
            None => None
        }
    }


    pub fn showmount_scan(&self, username: &str) -> Result<(), Box<dyn Error>> {
        println!("Running \"showmount -e {}\" to list all NFS shares", self.ip);
        let filename = format!("{}/nfs_shares", self.ip);
        create_output_file(username, &filename)?;

        // Obtain a file handle with write permissions
        let file_handle = OpenOptions::new()
                                      .write(true)
                                      .open(&filename)?;

        // Run the showmount command with -e, and use the file handle for stdout
        Command::new("showmount")
                .arg("-e")
                .arg(self.ip.to_string())
                .stdout(file_handle)
                .output()?;

        println!("\tCompleted scan for NFS shares");
        Ok(())
    }


    pub fn web_bundle(&self, username: &str, protocol: &str, ports: &Vec<String>) -> Result<(), Box<dyn Error>> {
        let target = match self.hostname() {
                Some(hostname) => hostname.to_string(),
                None => self.ip().to_string()
        };
        let target = target.as_str();

        if let Err(e) = self.bulk_nikto(&username, protocol, target, ports) {
            eprintln!("{}", e);
        }

        match self.bulk_gobuster(&username, protocol, target, ports) {
            Ok(web_dirs) => {
                if let Err(e) = self.bulk_wfuzz(&username, protocol, web_dirs) {
                    return Err(e)
                }
            },
            Err(e) => return Err(e)
        };

        Ok(())
    }


    pub fn wfuzz_scan(&self, full_target: &str) -> Result<Vec<String>, Box<dyn Error>>  {
        println!("Starting wfuzz scan for {}", full_target);
        // Format a string to pass to wfuzz
        let wfuzz_arg = format!("{}/FUZZ", full_target);
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
                            .output()?;

        // Grab the output and convert it to a string
        let wfuzz = String::from_utf8(wfuzz.stdout).unwrap();
        // Remove whitespace
        let wfuzz = wfuzz.trim();
        // Split it by newlines and allow it to be mutable
        let wfuzz: Vec<String> = wfuzz.split("\n")
                                      .map(|s| s.trim().to_string())
                                      .collect();

        // Some of this is garbage banner stuff, so set offsets to filter that out
        let header_elements_end = 5;
        let footer_elements_begin = wfuzz.len() - 4;

        let mut wfuzz_out = vec![];
        for (index, found) in wfuzz.iter().enumerate() {
            // The first banner is useful
            if index == 0 {
                wfuzz_out.push(String::from(found))
            }
            // As is the third banner
            else if index == 2 {
                wfuzz_out.push(String::from(found))
            }
            // The other useful banners fall between these two offsets
            else if header_elements_end <= index && index < footer_elements_begin {
                wfuzz_out.push(String::from(found))
            }
        }
        println!("\tCompleted wfuzz scan for {}", full_target);

        // Return wfuzz results
        Ok(wfuzz_out)
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


pub fn create_dir(username: &str, dir_name: &str) -> Result<(), Box<dyn Error>> {
    println!("Creating directory \"{}\" to store resulting files in", dir_name);
    // Create a file as the provided user with the desired name
    Command::new("sudo")
            .arg("-u")
            .arg(username)
            .arg("mkdir")
            .arg(dir_name)
            .output()?;

    Ok(())
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
    // Return an error if result was not [48, 10] (ie ascii "0\n") because we don't have sudo permissions
    if !(sudo[0] == 48 && sudo[1] == 10) {
        return Err("\"imd\" needs elevated privileges - please run with \"sudo\"".into())
    }

    Ok(())
}


pub fn target_discovery(target_machine: &TargetMachine, username: &str) -> Result<(), Box<dyn Error>> {
    // Convert the IP address to a string once for later use
    let ip_address = target_machine.ip().to_string();
    // Convert the hostname to an Option<String> once for later use
    let hostname = match &target_machine.hostname() {
        Some(hostname) => Some(hostname.to_string()),
        None => None
    };

    // Check /etc/hosts for the IP/hostname combo if there is a hostname
    if hostname.is_some() {
        target_machine.add_to_hosts()?;
    }

    // Ping the machine to make sure it is alive and reachable
    target_machine.check_connection()?;

    // Create directory for storing things in
    create_dir(username,&ip_address)?;

    // Run an nmap scan on all tcp ports
    target_machine.nmap_scan_all_tcp(&username)?;

    // Run a showmount scan
    target_machine.showmount_scan(&username)?;

    // Run a common-port nmap scan with service discovery
    let parsed_nmap = target_machine.nmap_scan_common(&username);
    let parsed_nmap = match parsed_nmap {
        Ok(parsed_nmap) => parsed_nmap,
        Err(e) => {
            eprintln!("{}", e);
            None
        }
    };

    // Remake the TargetMachine, this time with services known
    let target_machine = TargetMachine::new(*target_machine.ip(), hostname, parsed_nmap);

    match target_machine.services() {
        Some(services) => {
            if services.contains_key("http") {
                if let Err(e) = target_machine.web_bundle(&username, "http", services.get("http").unwrap()){
                    eprintln!("{}", e);
                }
            }
            if services.contains_key("ssl/http") {
                if let Err(e) = target_machine.web_bundle(&username, "https", services.get("ssl/http").unwrap()){
                    eprintln!("{}", e);
                }
            }
        },
        None => ()
    }

    Ok(())
}

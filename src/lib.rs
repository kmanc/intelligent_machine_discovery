use std::collections::HashMap;
use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::IpAddr;
use std::ops::Deref;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;

pub struct Config {
    targets: Vec<TargetMachine>,
    username: String,
}

#[derive(Clone)]
pub struct TargetMachine {
    ip: IpAddr,
    hostname: Option<String>
}

pub struct TargetMachineNmapped {
    ip: IpAddr,
    hostname: Option<String>,
    services: HashMap<String, Vec<String>>
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
                        targets.push(TargetMachine::new(last.unwrap(), None));
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
                        targets.push(TargetMachine::new(last.unwrap(), Some(arg.to_owned())));
                        // Set last to None
                        last = None;
                    }
                }
            }
        }

        // If the last argument supplied was an IP address it needs to be added to the list with no hostname
        if last != None {
            targets.push(TargetMachine::new(
                last.unwrap(),
                None
            ));
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
        if ping.contains("100% packet loss") || ping.contains("100.0% packet loss") {
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


    pub fn ip(&self) -> &IpAddr {
        &self.ip
    }


    pub fn new(ip: IpAddr, hostname: Option<String>) -> TargetMachine {
        TargetMachine{
            ip,
            hostname
        }
    }


    fn nmap_scan_common(&self, username: &str) -> Result<TargetMachineNmapped, Box<dyn Error>> {
        println!("Running \"nmap -sV {}\" (plus a few NSE scripts) for information on common ports", &self.ip().to_string());
        // Format filename for use in the nmap function and parser
        let filename = format!("{}/nmap_common", &self.ip().to_string());
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
                           .arg(&self.ip().to_string())
                           .output()?;

        // Grab the output and convert it to a string
        let nmap = String::from_utf8(nmap.stdout).unwrap();
        // Write the output to a file for the user in a way that allows for later use
        writeln!(&file_handle, "{}", &nmap)?;
        // Convert it to a vector by splitting on newlines - also trim each line
        let nmap: Vec<String> = nmap.split("\n")
                                    .map(|s| s.trim().to_string())
                                    .collect();

        println!("\tCompleted nmap scan on {}'s common ports", &self.ip().to_string());
        println!("Reading results from \"nmap -sV {}\" to determine next steps", &self.ip().to_string());

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

        let hostname = match self.hostname() {
            Some(hostname) => Some(hostname.to_string()),
            None => None
        };

        // Return the map of services and ports we found
        Ok(TargetMachineNmapped::new(
            *self.ip(),
            hostname,
            service_hashmap
        ))
    }
}


impl TargetMachineNmapped {
    pub fn hostname(&self) -> Option<&String> {
        match &self.hostname {
            Some(hostname) => Some(hostname),
            None => None
        }
    }


    pub fn ip(&self) -> &IpAddr {
        &self.ip
    }


    pub fn new(ip: IpAddr, hostname: Option<String>, services: HashMap<String, Vec<String>>) -> TargetMachineNmapped {
        TargetMachineNmapped{
            ip,
            hostname,
            services
        }
    }


    pub fn services(&self) -> &HashMap<String, Vec<String>> {
        &self.services
    }


    pub fn web_bundle(&self, username: Arc<String>, protocol: Arc<String>, ports: Arc<&Vec<String>>) -> Result<(), Box<dyn Error>> {
        let ip = self.ip().to_string();
        let ip = Arc::new(ip);

        let target = match self.hostname() {
            Some(hostname) => hostname.to_string(),
            None => self.ip().to_string()
        };
        let target = Arc::new(target);

        // Clone Arcs for some stuff for use in threads
        let arc_ip = Arc::clone(&ip);
        let arc_username = Arc::clone(&username);
        let arc_protocol = Arc::clone(&protocol);
        let arc_target = Arc::clone(&target);
        let arc_ports = Arc::clone(&ports);

        match bulk_gobuster(arc_ip, arc_username, arc_protocol, arc_target, arc_ports) {
            Ok(web_dirs) => {
                let arc_ip = Arc::clone(&ip);
                let arc_username = Arc::clone(&username);
                let arc_protocol = Arc::clone(&protocol);
                if let Err(e) = bulk_wfuzz(&**arc_ip, &**arc_username, &**arc_protocol, web_dirs) {
                    return Err(e)
                }
            },
            Err(e) => return Err(e)
        };

        // Clone Arcs again for more threading
        let arc_ip = Arc::clone(&ip);
        let arc_username = Arc::clone(&username);
        let arc_protocol = Arc::clone(&protocol);
        let arc_target = Arc::clone(&target);
        let arc_ports = Arc::clone(&ports);
        if let Err(e) = bulk_nikto(arc_ip, arc_username, arc_protocol, arc_target, arc_ports) {
            eprintln!("{}", e);
        }

        Ok(())
    }
}


fn bulk_gobuster(ip: Arc<String>, username: Arc<String>, protocol: Arc<String>, target: Arc<String>, ports: Arc<&Vec<String>>) -> Result<Arc<Mutex<Vec<String>>>, Box<dyn Error>> {
    let web_dirs = Arc::new(Mutex::new(vec![]));
    let mut gobuster_threads = vec![];
    //let ports = Arc::try_unwrap(ports).unwrap().to_owned();
    for port in ports.iter().cloned() {
        let ip = Arc::clone(&ip);
        let username = Arc::clone(&username);
        let protocol = Arc::clone(&protocol);
        let target = Arc::clone(&target);
        let port = port.to_owned();
        gobuster_threads.push(thread::spawn({
            let vec_clone = Arc::clone(&web_dirs);
            move || {
                match gobuster_scan(ip.deref(), username.deref(), protocol.deref(), target.deref(), &port) {
                    Ok(gobuster) => {
                        for dir in gobuster.iter() {
                            let dir: Vec<&str> = dir.split(" ").collect();
                            let finding = format!("{}://{}:{}{}", protocol, target, port, dir[0]);
                            let mut v = vec_clone.lock().unwrap();
                            v.push(finding);
                        }
                    },
                    Err(e) => eprintln!("{}", e)
                }
            }
        }));
    }

    for t in gobuster_threads {
        t.join().unwrap();
    }

    Ok(web_dirs)
}


fn bulk_nikto(ip: Arc<String>, username: Arc<String>, protocol: Arc<String>, target: Arc<String>, ports: Arc<&Vec<String>>) -> Result<(), Box<dyn Error>> {
    let mut nikto_threads = vec![];
    for port in ports.iter() {
        let ip = Arc::clone(&ip);
        let username = Arc::clone(&username);
        let protocol = Arc::clone(&protocol);
        let target = Arc::clone(&target);
        let port = port.to_owned();
        nikto_threads.push(thread::spawn(move || {
            if let Err(e) = nikto_scan(ip.deref(), username.deref(), protocol.deref(), target.deref(), port){
                eprintln!("{}", e);
            }
        }));
    }
    // Make sure all nikto threads complete
    for thread in nikto_threads {
        if let Err(e) = thread.join(){
            eprintln!("{:?}", e);
        }
    }


    Ok(())
}


fn bulk_wfuzz(ip: &str, username: &str, protocol: &str, targets: Arc<Mutex<Vec<String>>>) -> Result<(), Box<dyn Error>> {
    let filename = format!("{}/wfuzz_{}", ip, protocol);
    create_output_file(username, &filename)?;

    // Obtain a file handle with write permissions
    let file_handle = OpenOptions::new()
                                  .write(true)
                                  .open(&filename)?;

    let web_files = Arc::new(Mutex::new(vec![]));
    let mut wfuzz_threads = vec![];
    let targets = Arc::try_unwrap(targets).unwrap().into_inner().unwrap();
    let targets = Arc::new(targets);
    let targets = Arc::clone(&targets);
    for target in targets.iter().cloned() {
        wfuzz_threads.push(thread::spawn({
            let vec_clone = Arc::clone(&web_files);
            move || {
                match wfuzz_scan(&target) {
                    Ok(wfuzz) => {
                        for file in wfuzz.iter() {
                            let mut v = vec_clone.lock().unwrap();
                            v.push(file.to_string());
                        }
                    },
                    Err(e) => eprintln!("{}", e)
                }
            }
        }));
    }

    for t in wfuzz_threads {
        t.join().unwrap();
    }

    let web_files = Arc::try_unwrap(web_files).unwrap().into_inner().unwrap();
    writeln!(&file_handle, "{}", web_files.join("\n"))?;

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


fn gobuster_scan(ip: &str, username: &str, protocol: &str, target: &str, port: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let gobuster_arg = format!("{}://{}:{}", protocol, target, port);
    println!("Starting gobuster directory scan on {}", &gobuster_arg);
    let filename = format!("{}/dirs_{}_port_{}", ip, target, port);
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


fn nikto_scan(ip: &str, username: &str, protocol: &str, target: &str, port: String) -> Result<(), Box<dyn Error>> {
    let nikto_arg = format!("{}://{}:{}", protocol, target, port);
    println!("Starting a 60 second max nikto scan on {}", nikto_arg);
    let filename = format!("{}/nikto_{}_port_{}", ip, target, port);
    create_output_file(username, &filename)?;

    // Obtain a file handle with write permissions
    let file_handle = OpenOptions::new()
                                  .write(true)
                                  .open(filename)?;

    // Run the nikto command with a few flags, and use the file handle for stdout
    Command::new("nikto")
            .arg("-host")
            .arg(&nikto_arg)
            .arg("-maxtime")
            .arg("60")
            .stdout(file_handle)
            .output()?;

    println!("\tCompleted nikto scan on {}", nikto_arg);
    Ok(())
}


fn nmap_scan_all_tcp(ip: &String, username: &str) -> Result<(), Box<dyn Error>> {
    println!("Running \"nmap -p- {}\" for information on all TCP ports", ip);
    let filename = format!("{}/nmap_all_tcp", ip);
    create_output_file(username, &filename)?;

    // Obtain a file handle with write permissions
    let file_handle = OpenOptions::new()
                                  .write(true)
                                  .open(&filename)?;

    // Run an nmap command with -p-, and use the file handle for stdout
    Command::new("nmap")
            .arg("-p-")
            .arg(&*ip)
            .stdout(file_handle)
            .output()?;

    println!("\tCompleted nmap scan on all of {}'s TCP ports", ip);

    Ok(())
}


fn showmount_scan(ip: &str, username: &str) -> Result<(), Box<dyn Error>> {
    println!("Running \"showmount -e {}\" to list all NFS shares", ip);
    let filename = format!("{}/nfs_shares", ip);
    create_output_file(username, &filename)?;

    // Obtain a file handle with write permissions
    let file_handle = OpenOptions::new()
                                  .write(true)
                                  .open(&filename)?;

    // Run the showmount command with -e, and use the file handle for stdout
    Command::new("showmount")
            .arg("-e")
            .arg(ip)
            .stdout(file_handle)
            .output()?;

    println!("\tCompleted scan for NFS shares");
    Ok(())
}


fn wfuzz_scan(full_target: &str) -> Result<Vec<String>, Box<dyn Error>>  {
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


pub fn target_discovery(target_machine: &TargetMachine, username: Arc<String>) -> Result<(), Box<dyn Error>> {
    // Convert the IP address to a string once for later use
    let ip = target_machine.ip().to_string();
    // Convert the hostname to an Option<String> once for later use
    if target_machine.hostname().is_some() {
        // Check /etc/hosts for the IP/hostname combo and add it if it isn't there
        target_machine.add_to_hosts()?;
    }

    // Ping the machine to make sure it is alive and reachable
    target_machine.check_connection()?;

    // Create directory for storing things in
    create_dir(&username,&ip)?;

    // Create thread vector for nmap and showmount
    let mut discovery_threads = vec![];

    // Create Arcs for IP and username so they can be cloned and sent to the threads
    let ip= Arc::new(ip);

    // Clone the Arcs for the thread
    let arc_ip = Arc::clone(&ip);
    let arc_username = Arc::clone(&username);

    // Run an nmap scan on all tcp ports in a thread
    discovery_threads.push(thread::spawn(move || {
            if let Err(e) = nmap_scan_all_tcp(arc_ip.deref(), arc_username.deref()){
                eprintln!("{}", e);
            }
    }));

    // Re-clone the Arcs for the thread
    let arc_ip = Arc::clone(&ip);
    let arc_username = Arc::clone(&username);

    // Run a showmount scan in a thread
    discovery_threads.push(thread::spawn(move || {
            if let Err(e) = showmount_scan(arc_ip.deref(), arc_username.deref()){
                eprintln!("{}", e);
            }
    }));

    // Run a common-port nmap scan with service discovery and return a new TargetMachineNmapped, with service data
    let target_machine_nmapped = target_machine.nmap_scan_common(&username)?;

    if target_machine_nmapped.services().contains_key("http") {
        let arc_username = Arc::clone(&username);
        let arc_protocol = Arc::new("http".to_string());
        let arc_services = Arc::new(target_machine_nmapped.services().get("http").unwrap());
        if let Err(e) = target_machine_nmapped.web_bundle(arc_username, arc_protocol, arc_services) {
            eprintln!("{}", e);
        }
    }
    if target_machine_nmapped.services().contains_key("ssl/http") {
        let arc_username = Arc::clone(&username);
        let arc_protocol = Arc::new("https".to_string());
        let arc_services = Arc::new(target_machine_nmapped.services().get("ssl/http").unwrap());
        if let Err(e) = target_machine_nmapped.web_bundle(arc_username, arc_protocol, arc_services) {
            eprintln!("{}", e);
        }
    }

    // Make sure both the nmap -p- and showmount threads complete
    for thread in discovery_threads {
        if let Err(e) = thread.join(){
            eprintln!("{:?}", e);
        }
    }

    Ok(())
}
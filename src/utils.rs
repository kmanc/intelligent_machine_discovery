use indicatif::MultiProgress;
use std::collections::HashMap;
use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::sync::Arc;


pub fn add_to_etc_hosts(bar_container: Arc<MultiProgress>, hostname: &str, ip_address: &str) -> Result<(), Box<dyn Error>> {
    // Create a bar for messaging progress
    let bar = bar_container.add(imd::make_new_bar());
    
    // All messages logged will start with the same thing so create it once up front
    let starter = imd::make_message_starter(ip_address, "Adding to /etc/hosts");
    let starter_clone = starter.clone();

    // Report that we are adding the machine to /etc/hosts
    bar.set_message(starter);

    // Open the /etc/hosts files and read it line by line
    let host_file = File::open("/etc/hosts")?;
    let reader = BufReader::new(host_file);
    for line in reader.lines() {
        let line = line?;
        // If a line contains the ip address and hostname already, let the user know it is already there and exit
        if line.contains(ip_address) && line.contains(hostname) {
            let output = imd::report_neutral("Entry already in /etc/hosts, skipping");
            bar.finish_with_message(format!("{starter_clone}{output}"));
            return Ok(())
        }
    }

    // If we didn't already return, add the entry to the /etc/hosts file because it wasn't there
    let host_file = OpenOptions::new()
        .append(true)
        .open("/etc/hosts")?;

    writeln!(&host_file, "{} {}", ip_address, hostname)?;

    // Report that we were successful in adding to /etc/hosts
    let output = imd::report_good("Done");
    bar.finish_with_message(format!("{starter_clone}{output}"));

    Ok(())
}


pub fn create_dir(bar_container: Arc<MultiProgress>, user: Arc<imd::IMDUser>, ip_address: &str) -> Result<(), Box<dyn Error>> {
    // Create a bar for messaging progress
    let bar = bar_container.add(imd::make_new_bar());
    
    // All messages logged will start with the same thing so create it once up front
    let starter = imd::make_message_starter(ip_address, "Creating directory to store results in");
    let starter_clone = starter.clone();

    // Report that we are creating a dir for the results
    bar.set_message(starter);

    // If it fails, it's probably because the directory already exists (not 100%, but pretty likely), so report that and move on
    if fs::create_dir(ip_address).is_err() {
        let output = imd::report_neutral("Directory already exists, skipping");
        bar.finish_with_message(format!("{starter_clone}{output}"));
        return Ok(())
    }

    // Change ownership of the directory to the logged in user from Args
    imd::change_owner(ip_address, user)?;

    // Report that we were successful in creating the results directory
    let output = imd::report_good("Done");
    bar.finish_with_message(format!("{starter_clone}{output}"));

    Ok(())
}


pub fn parse_port_scan(bar_container: Arc<MultiProgress>, ip_address: &str, port_scan: String) -> HashMap<String, Vec<String>> {
    // Create a bar for messaging progress
    let bar = bar_container.add(imd::make_new_bar());
    
    // All messages logged will start with the same thing so create it once up front
    let starter = imd::make_message_starter(ip_address, "Parsing port scan to determine next steps");
    let starter_clone = starter.clone();
    
    // Report that we are parsing the port scan
    bar.set_message(starter);

    // Prep the scan string for searching by splitting it to a vector of lines, trimming each line, and removing lines that start with "|" or "SF:"
    let port_scan: Vec<String> = port_scan
        .split('\n')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.starts_with('|'))
        .filter(|s| !s.starts_with("SF:"))
        .collect();

    // Define a list of services that we will do something about
    let services = vec!["http", "ssl/http"];

    // Create a new HashMap to store results in
    let mut services_map: HashMap<String, Vec<String>> = HashMap::new();

    // Iterate over the port scan and find ports that host services we are looking for. Add those service / port pairs to the map
    for line in port_scan {
        for service in &services {
            if line.contains(service) && line.contains("open") {
                let port = line.split('/').collect::<Vec<&str>>()[0];
                let service = match service {
                    &"ssl/http" => "https",
                    _ => service,
                };
                services_map.entry(service.to_string()).or_default().push(port.to_string());
            }
        }
    }

    // Report that we were successful in parsing the port scan
    let output = imd::report_good("Done");
    bar.finish_with_message(format!("{starter_clone}{output}"));

    services_map
}

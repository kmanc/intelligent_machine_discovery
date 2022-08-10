use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::sync::{Arc, mpsc};


pub fn add_to_etc_hosts(tx: mpsc::Sender<String>, hostname: &str, ip_address: &str) -> Result<(), Box<dyn Error>> {
    // Report that we are adding the machine to /etc/hosts
    let log = imd::format_log(ip_address, "Adding to /etc/hosts");
    tx.send(log)?;

    // Open the /etc/hosts files and read it line by line
    let host_file = File::open("/etc/hosts")?;
    let reader = BufReader::new(host_file);
    for line in reader.lines() {
        let line = line.unwrap();
        // If a line contains the ip address and hostname already, let the user know it is already there and exit
        if line.contains(ip_address) && line.contains(hostname) {
            let log = imd::format_log(ip_address, "Entry already in /etc/hosts, skipping");
            tx.send(log)?;
            return Ok(())
        }
    }

    // If we didn't already return, add the entry to the /etc/hosts file because it wasn't there
    let host_file = OpenOptions::new().append(true)
                                      .open("/etc/hosts")?;

    writeln!(&host_file, "{} {}", ip_address, hostname)?;

    Ok(())
}


pub fn create_dir(tx: mpsc::Sender<String>, user: Arc<imd::IMDUser>, ip_address: &str) -> Result<(), Box<dyn Error>> {
    // Report that we are creating the directory
    let log = imd::format_log(ip_address, "Creating directory to store results in");
    tx.send(log)?;

    // If it fails, it's probably because the directory already exists (not 100%, but pretty likely), so report that and move on
    if fs::create_dir(ip_address).is_err() {
        let log = imd::format_log(ip_address, "Directory already exists, skipping");
        tx.send(log)?;
    }

    // Change ownership of the directory to the logged in user from Args
    imd::change_owner(ip_address, user)?;

    Ok(())
}

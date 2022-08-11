use std::error::Error;
use std::io::Write;
use std::sync::{Arc, mpsc};


pub fn directory_scan(tx: mpsc::Sender<String>, user: Arc<imd::IMDUser>, ip_address: &str, protocol: &str, port: &str, web_location: &str) -> Result<(), Box<dyn Error>> {
    // Report that we are scanning for web directories
    let log = imd::format_log(ip_address, &format!("Scanning for web directories on port {port} with 'feroxbuster -q -n'"));
    tx.send(log)?;

    let full_location = format!("{protocol}://{web_location}:{port}");

    // Run the vuln scan and capture the output
    let args = vec!["-q", "-n", "-w", "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt", "-u", &full_location];
    let command = imd::get_command_output("feroxbuster", args)?;

    // For some reason this output has double "\n" at the end of each line, so we fix that
    let command = command.replace("\n\n", "\n");

    // Create a file for the results
    let output_filename = format!("{ip_address}/web_dirs_port_{port}");
    let mut f = imd::create_file(user, &output_filename)?;

    // Write the command output to the file
    writeln!(f, "{command}")?;

    // Report that we completed the web vuln scan
    let log = imd::format_log(ip_address, &format!("Web port {port} directory scan complete"));
    tx.send(log)?;

    Ok(())
}


pub fn file_scan(tx: mpsc::Sender<String>, user: Arc<imd::IMDUser>, ip_address: &str, port: &str, full_location: &str) -> Result<(), Box<dyn Error>> {
    // Report that we are scanning for web directories
    let log = imd::format_log(ip_address, &format!("Scanning for web files on port {port} with 'feroxbuster -q -n'"));
    tx.send(log)?;

    // Run the vuln scan and capture the output
    let args = vec!["-q", "-n", "-w", "/usr/share/wordlists/seclists/raft-medium-files.txt", "-u", &full_location];
    let command = imd::get_command_output("feroxbuster", args)?;

    // Create a file for the results
    let output_filename = format!("{ip_address}/web_files_port_{port}");
    let mut f = imd::create_file(user, &output_filename)?;

    // Write the command output to the file
    writeln!(f, "{command}")?;

    // Report that we completed the web vuln scan
    let log = imd::format_log(ip_address, &format!("Web port {port} file scan complete"));
    tx.send(log)?;

    Ok(())
}


pub fn vuln_scan(tx: mpsc::Sender<String>, user: Arc<imd::IMDUser>, ip_address: &str, protocol: &str, port: &str, web_location: &str) -> Result<(), Box<dyn Error>> {
    // Report that we are scanning for web vulnerabilities
    let log = imd::format_log(ip_address, &format!("Scanning for web vulnerabilities on port {port} with 'nikto -host'"));
    tx.send(log)?;

    let full_location = format!("{protocol}://{web_location}:{port}");

    // Run the vuln scan and capture the output
    let args = vec!["-host", &full_location, "-maxtime", "60"];
    let command = imd::get_command_output("nikto", args)?;

    // Create a file for the results
    let output_filename = format!("{ip_address}/web_vulns_port_{port}");
    let mut f = imd::create_file(user, &output_filename)?;

    // Write the command output to the file
    writeln!(f, "{command}")?;

    // Report that we completed the web vuln scan
    let log = imd::format_log(ip_address, &format!("Web port {port} vuln scan complete"));
    tx.send(log)?;

    Ok(())
}

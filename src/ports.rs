use std::error::Error;
use std::io::Write;
use std::sync::{Arc, mpsc};


pub fn all_tcp_ports(tx: mpsc::Sender<String>, user: Arc<imd::IMDUser>, ip_address: &str) -> Result<(), Box<dyn Error>> {
    // Report that we are scanning all TCP ports
    let log = imd::format_log(ip_address, "Scanning all TCP ports using 'nmap -p- -Pn'", None);
    tx.send(log)?;

    // Run the port scan and capture the output
    let args = vec!["-p-", "-Pn", ip_address];
    let command = imd::get_command_output("nmap", args)?;

    // Create a file for the results
    let output_filename = format!("{ip_address}/all_tcp_ports");
    let mut f = imd::create_file(user, &output_filename)?;

    // Write the command output to the file
    writeln!(f, "{command}")?;

    // Report that we completed the TCP port scan
    let log = imd::format_log(ip_address, "All TCP port scan complete", Some(imd::Color::Green));
    tx.send(log)?;

    Ok(())
}


pub fn common_tcp_ports(tx: &mpsc::Sender<String>, user: Arc<imd::IMDUser>, ip_address: &str) -> Result<String, Box<dyn Error>> {
    // Report that we are scanning all TCP ports
    let log = imd::format_log(ip_address, "Scanning common TCP ports for services with 'nmap -sV -Pn --script http-robots.txt --script http-title --script ssl-cert --script ftp-anon'", None);
    tx.send(log)?;

    // Run the port scan and capture the output
    let args = vec!["-sV", "-Pn", "--script", "http-robots.txt", "--script", "http-title", "--script", "ssl-cert", "--script", "ftp-anon", ip_address];
    let command = imd::get_command_output("nmap", args)?;

    // Create a file for the results
    let output_filename = format!("{ip_address}/common_tcp_ports");
    let mut f = imd::create_file(user, &output_filename)?;

    // Write the command output to the file
    writeln!(f, "{command}")?;

    // Report that we completed the TCP port scan
    let log = imd::format_log(ip_address, "Common TCP port scan complete", Some(imd::Color::Green));
    tx.send(log)?;

    Ok(command)
}

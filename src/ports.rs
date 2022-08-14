use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::error::Error;
use std::io::Write;
use std::sync::Arc;


pub fn all_tcp_ports(user: Arc<imd::IMDUser>, ip_address: &str, bar_container: Arc<MultiProgress>, bar_style: ProgressStyle) -> Result<(), Box<dyn Error>> {
    // Create a bar for messaging progress
    let bar = bar_container.add(ProgressBar::new(0).with_style(bar_style));
    
    // Report that we are adding the machine to /etc/hosts
    bar.set_message(format!("{}{}", imd::format_ip_address(ip_address), "Scanning all TCP ports using 'nmap -p- -Pn'"));

    // Run the port scan and capture the output
    let args = vec!["-p-", "-Pn", ip_address];
    let command = imd::get_command_output("nmap", args)?;

    // Create a file for the results
    let output_filename = format!("{ip_address}/all_tcp_ports");
    let mut f = imd::create_file(user, &output_filename)?;

    // Write the command output to the file
    writeln!(f, "{command}")?;

    // Report that we were successful in adding to /etc/hosts
    bar.finish_with_message(format!("{}{} {}", imd::format_ip_address(ip_address), "Scanning all TCP ports using 'nmap -p- -Pn'", imd::color_text("✔️ Done", Some(imd::Color::Green))));

    Ok(())
}


pub fn common_tcp_ports(user: Arc<imd::IMDUser>, ip_address: &str, bar_container: Arc<MultiProgress>, bar_style: ProgressStyle) -> Result<String, Box<dyn Error>> {
    // Create a bar for messaging progress
    let bar = bar_container.add(ProgressBar::new(0).with_style(bar_style));
    
    // Report that we are adding the machine to /etc/hosts
    bar.set_message(format!("{}{}", imd::format_ip_address(ip_address), "Scanning common TCP ports for services with 'nmap -sV -Pn --script http-robots.txt --script http-title --script ssl-cert --script ftp-anon'"));


    // Run the port scan and capture the output
    let args = vec!["-sV", "-Pn", "--script", "http-robots.txt", "--script", "http-title", "--script", "ssl-cert", "--script", "ftp-anon", ip_address];
    let command = imd::get_command_output("nmap", args)?;

    // Create a file for the results
    let output_filename = format!("{ip_address}/common_tcp_ports");
    let mut f = imd::create_file(user, &output_filename)?;

    // Write the command output to the file
    writeln!(f, "{command}")?;

    // Report that we were successful in adding to /etc/hosts
    bar.finish_with_message(format!("{}{} {}", imd::format_ip_address(ip_address), "Scanning common TCP ports for services with 'nmap -sV -Pn --script http-robots.txt --script http-title --script ssl-cert --script ftp-anon'", imd::color_text("✔️ Done", Some(imd::Color::Green))));

    Ok(command)
}

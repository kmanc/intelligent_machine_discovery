use indicatif::MultiProgress;
use std::error::Error;
use std::io::Write;
use std::sync::Arc;


pub fn all_tcp_ports(bar_container: Arc<MultiProgress>, user: Arc<imd::IMDUser>, ip_address: &str) -> Result<(), Box<dyn Error>> {
    // Create a bar for messaging progress
    let bar = bar_container.add(imd::make_new_bar());

    // All messages logged will start with the same thing so create it once up front
    let starter = imd::make_message_starter(ip_address, "Scanning all TCP ports using 'nmap -p- -Pn'");
    let starter_clone = starter.clone();
    
    // Report that we are scanning all TCP ports
    bar.set_message(starter);

    // Run the port scan and capture the output
    let args = vec!["-p-", "-Pn", ip_address];
    let command = imd::get_command_output("nmap", args)?;

    // Create a file for the results
    let output_filename = format!("{ip_address}/all_tcp_ports");
    let mut f = imd::create_file(user, &output_filename)?;

    // Write the command output to the file
    writeln!(f, "{command}")?;

    // Report that we were successful in adding to /etc/hosts
    let output = imd::report_good("Done");
    bar.finish_with_message(format!("{starter_clone}{output}"));

    Ok(())
}


pub fn common_tcp_ports(bar_container: Arc<MultiProgress>, user: Arc<imd::IMDUser>, ip_address: &str) -> Result<String, Box<dyn Error>> {
    // Create a bar for messaging progress
    let bar = bar_container.add(imd::make_new_bar());

    // All messages logged will start with the same thing so create it once up front
    let starter = imd::make_message_starter(ip_address, "Scanning common TCP ports for services with 'nmap -sV -Pn --script http-robots.txt --script http-title --script ssl-cert --script ftp-anon'");
    let starter_clone = starter.clone();
    
    // Report that we are scanning all common TCP ports
    bar.set_message(starter);

    // Run the port scan and capture the output
    let args = vec!["-sV", "-Pn", "--script", "http-robots.txt", "--script", "http-title", "--script", "ssl-cert", "--script", "ftp-anon", ip_address];
    let command = imd::get_command_output("nmap", args)?;

    // Create a file for the results
    let output_filename = format!("{ip_address}/common_tcp_ports");
    let mut f = imd::create_file(user, &output_filename)?;

    // Write the command output to the file
    writeln!(f, "{command}")?;

    // Report that we were successful in adding to /etc/hosts
    let output = imd::report_good("Done");
    bar.finish_with_message(format!("{starter_clone}{output}"));

    Ok(command)
}
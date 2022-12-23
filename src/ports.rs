use std::error::Error;
use std::io::Write;
use std::sync::Arc;

pub fn all_tcp_ports(args_bundle: &Arc<imd::DiscoveryArgs>) -> Result<(), Box<dyn Error>> {
    // Add a bar for messaging progress
    let bar = imd::add_new_bar(args_bundle.bars_container());

    // Prevent borrow-after-freed
    let ip_string = &args_bundle.machine().ip_address().to_string();

    // All messages logged will start with the same thing so create it once up front
    let starter =
        imd::make_message_starter(ip_string, "Scanning all TCP ports using 'nmap -p- -Pn'");

    // Report that we are scanning all TCP ports
    bar.set_message(starter.clone());

    // Run the port scan and capture the output
    let args = vec!["-p-", "-Pn", ip_string];
    let command = imd::get_command_output("nmap", args)?;

    // Create a file for the results
    let output_file = format!("{}/all_tcp_ports", ip_string);
    let mut f = imd::create_file(args_bundle.user(), &output_file)?;

    // Write the command output to the file
    writeln!(f, "{command}")?;

    // Report that we were successful in adding to /etc/hosts
    let output = imd::report(&imd::IMDOutcome::Good, "Done");
    bar.finish_with_message(format!("{starter}{output}"));

    Ok(())
}

pub fn common_tcp_ports(args_bundle: &Arc<imd::DiscoveryArgs>) -> Result<String, Box<dyn Error>> {
    // Add a bar for messaging progress
    let bar = imd::add_new_bar(args_bundle.bars_container());

    // Prevent borrow-after-freed
    let ip_string = &args_bundle.machine().ip_address().to_string();

    // All messages logged will start with the same thing so create it once up front
    let starter = imd::make_message_starter(ip_string, "Scanning common TCP ports for services with 'nmap -sV -Pn --script http-robots.txt --script http-title --script ssl-cert --script ftp-anon'");

    // Report that we are scanning all common TCP ports
    bar.set_message(starter.clone());

    // Run the port scan and capture the output
    let args = vec![
        "-sV",
        "-Pn",
        "--script",
        "http-robots.txt",
        "--script",
        "http-title",
        "--script",
        "ssl-cert",
        "--script",
        "ftp-anon",
        ip_string,
    ];
    let command = imd::get_command_output("nmap", args)?;

    // Create a file for the results
    let output_file = format!("{}/common_tcp_ports", ip_string);
    let mut f = imd::create_file(args_bundle.user(), &output_file)?;

    // Write the command output to the file
    writeln!(f, "{command}")?;

    // Report that we were successful in adding to /etc/hosts
    let output = imd::report(&imd::IMDOutcome::Good, "Done");
    bar.finish_with_message(format!("{starter}{output}"));

    Ok(command)
}

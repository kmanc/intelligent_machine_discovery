use std::io::Write;
use std::sync::Arc;

pub fn all_tcp_ports(args_bundle: &Arc<imd::DiscoveryArgs>) {
    // Add a bar for messaging progress
    let bar = args_bundle.add_new_bar();

    // Prevent borrow-after-freed
    let ip_string = &args_bundle.machine().ip_address().to_string();

    // All messages logged will start with the same thing so create it once up front
    let starter =
        imd::make_message_starter(ip_string, "Scanning all TCP ports using 'nmap -p- -Pn'");

    // Report that we are scanning all TCP ports
    bar.set_message(starter.clone());

    // Run the port scan and capture the output
    let args = vec!["-p-", "-Pn", ip_string];
    let command = match imd::get_command_output("nmap", args) {
        Err(_) => {
            let output = imd::report(&imd::IMDOutcome::Bad, "Problem running the nmap command");
            bar.finish_with_message(format!("{starter}{output}"));
            return;
        }
        Ok(command) => command,
    };

    // Create a file for the results
    let output_file = format!("{ip_string}/all_tcp_ports");
    let mut f = match imd::create_file(args_bundle.user(), &output_file) {
        Err(_) => {
            let output = imd::report(
                &imd::IMDOutcome::Bad,
                "Problem creating a file for the output of the nmap command",
            );
            bar.finish_with_message(format!("{starter}{output}"));
            return;
        }
        Ok(f) => f,
    };

    // Write the command output to the file
    if writeln!(f, "{command}").is_err() {
        let output = imd::report(
            &imd::IMDOutcome::Bad,
            "Problem writing the results of the nmap command",
        );
        bar.finish_with_message(format!("{starter}{output}"));
        return;
    };

    // Report that we were successful in adding to /etc/hosts
    let output = imd::report(&imd::IMDOutcome::Good, "Done");
    bar.finish_with_message(format!("{starter}{output}"));
}

pub fn common_tcp_ports(args_bundle: &Arc<imd::DiscoveryArgs>) -> String {
    // Add a bar for messaging progress
    let bar = args_bundle.add_new_bar();

    // Prevent borrow-after-freed
    let ip_string = &args_bundle.machine().ip_address().to_string();

    // All messages logged will start with the same thing so create it once up front
    let starter = imd::make_message_starter(ip_string, "Scanning common TCP ports for services with 'nmap -sV -Pn --script http-robots.txt,http-title,ssl-cert,ftp-anon'");

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
    let command = match imd::get_command_output("nmap", args) {
        Err(_) => {
            let output = imd::report(&imd::IMDOutcome::Bad, "Problem running the nmap command");
            bar.finish_with_message(format!("{starter}{output}"));
            return String::new();
        }
        Ok(command) => command,
    };

    // Create a file for the results
    let output_file = format!("{ip_string}/common_tcp_ports");
    let mut f = match imd::create_file(args_bundle.user(), &output_file) {
        Err(_) => {
            let output = imd::report(
                &imd::IMDOutcome::Bad,
                "Problem creating file for the output of the nmap command",
            );
            bar.finish_with_message(format!("{starter}{output}"));
            return String::new();
        }
        Ok(f) => f,
    };

    // Write the command output to the file
    if writeln!(f, "{command}").is_err() {
        let output = imd::report(
            &imd::IMDOutcome::Bad,
            "Problem writing the results of the nmap command",
        );
        bar.finish_with_message(format!("{starter}{output}"));
        return String::new();
    };

    // Report that we were successful in adding to /etc/hosts
    let output = imd::report(&imd::IMDOutcome::Good, "Done");
    bar.finish_with_message(format!("{starter}{output}"));

    command
}

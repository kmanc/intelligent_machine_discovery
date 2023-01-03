use std::io::Write;
use std::sync::Arc;

pub fn dir_and_file_scan(args_bundle: &Arc<imd::DiscoveryArgs>, protocol: &str, port: &str) {
    // Add a bar for messaging progress
    let bar = imd::add_new_bar(args_bundle.bars_container());

    let ip_string = &args_bundle.machine().ip_address().to_string();

    // All messages logged will start with the same thing so create it once up front
    let starter = imd::format_command_start(ip_string, 16, &format!("Scanning for web directories and files on port {port} with 'feroxbuster -q --thorough --time-limit 10m'"));

    // Report that we are scanning for web directories and files
    bar.set_message(starter.clone());

    let full_location = format!("{protocol}://{}:{port}", args_bundle.machine().web_target());

    // Run the vuln scan and capture the output
    let args = vec![
        "-q",
        "--thorough",
        "--time-limit",
        "10m",
        "--no-state",
        "-w",
        args_bundle.wordlist(),
        "-u",
        &full_location,
    ];
    let command = match imd::get_command_output("feroxbuster", args, &bar, &starter) {
        Err(_) => return,
        Ok(command) => command,
    };

    // For some reason this output has double "\n" at the end of each line, so we fix that
    let command = command.replace("\n\n", "\n");

    // Create a file for the results
    let output_file = format!("{ip_string}/web_dirs_and_files_port_{port}");
    let mut f = match imd::create_file(
        args_bundle.user(),
        &output_file,
        "feroxbuster",
        &bar,
        &starter,
    ) {
        Err(_) => return,
        Ok(f) => f,
    };

    // Write the command output to the file
    if writeln!(f, "{command}").is_err() {
        let output = imd::format_command_result(
            &imd::IMDOutcome::Bad,
            "Problem writing the results of the feroxbuster command",
        );
        bar.finish_with_message(format!("{starter}{output}"));
        return;
    };

    // Report that we were successful in adding to /etc/hosts
    let output = imd::format_command_result(&imd::IMDOutcome::Good, "Done");
    bar.finish_with_message(format!("{starter}{output}"));
}

pub fn vuln_scan(args_bundle: &Arc<imd::DiscoveryArgs>, protocol: &str, port: &str) {
    // Add a bar for messaging progress
    let bar = imd::add_new_bar(args_bundle.bars_container());

    let ip_string = &args_bundle.machine().ip_address().to_string();

    // All messages logged will start with the same thing so create it once up front
    let starter = imd::format_command_start(
        ip_string,
        16,
        &format!("Scanning for web vulnerabilities on port {port} with 'nikto -host -maxtime 60'"),
    );

    // Report that we are scanning for web vulnerabilities
    bar.set_message(starter.clone());

    let full_location = format!("{protocol}://{}:{port}", args_bundle.machine().web_target());

    // Run the vuln scan and capture the output
    let args = vec!["-host", &full_location, "-maxtime", "60"];
    let command = match imd::get_command_output("nikto", args, &bar, &starter) {
        Err(_) => return,
        Ok(command) => command,
    };

    // Create a file for the results
    let output_file = format!("{ip_string}/web_vulns_port_{port}");
    let mut f = match imd::create_file(args_bundle.user(), &output_file, "nikto", &bar, &starter) {
        Err(_) => return,
        Ok(f) => f,
    };

    // Write the command output to the file
    if writeln!(f, "{command}").is_err() {
        let output = imd::format_command_result(
            &imd::IMDOutcome::Bad,
            "Problem writing the results of the nikto command",
        );
        bar.finish_with_message(format!("{starter}{output}"));
        return;
    };

    // Report that we completed the web vuln scan
    let output = imd::format_command_result(&imd::IMDOutcome::Good, "Done");
    bar.finish_with_message(format!("{starter}{output}"));
}

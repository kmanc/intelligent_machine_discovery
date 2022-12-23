use std::error::Error;
use std::io::Write;
use std::sync::Arc;

pub fn dir_and_file_scan(
    args_bundle: &Arc<imd::DiscoveryArgs>,
    protocol: &str,
    port: &str,
) -> Result<(), Box<dyn Error>> {
    // Add a bar for messaging progress
    let bar = imd::add_new_bar(args_bundle.bars_container());

    let ip_string = &args_bundle.machine().ip_address().to_string();

    // All messages logged will start with the same thing so create it once up front
    let starter = imd::make_message_starter(ip_string, &format!("Scanning for web directories and files on port {port} with 'feroxbuster -q --thorough --time-limit 10m'"));

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
    let command = imd::get_command_output("feroxbuster", args)?;

    // For some reason this output has double "\n" at the end of each line, so we fix that
    let command = command.replace("\n\n", "\n");

    // Create a file for the results
    let output_file = format!("{}/web_dirs_and_files_port_{port}", ip_string);
    let mut f = imd::create_file(args_bundle.user(), &output_file)?;

    // Write the command output to the file
    writeln!(f, "{command}")?;

    // Report that we were successful in adding to /etc/hosts
    let output = imd::report(&imd::IMDOutcome::Good, "Done");
    bar.finish_with_message(format!("{starter}{output}"));

    Ok(())
}

pub fn vuln_scan(
    args_bundle: &Arc<imd::DiscoveryArgs>,
    protocol: &str,
    port: &str,
) -> Result<(), Box<dyn Error>> {
    // Add a bar for messaging progress
    let bar = imd::add_new_bar(args_bundle.bars_container());

    let ip_string = &args_bundle.machine().ip_address().to_string();

    // All messages logged will start with the same thing so create it once up front
    let starter = imd::make_message_starter(
        ip_string,
        &format!("Scanning for web vulnerabilities on port {port} with 'nikto -host -maxtime 60'"),
    );

    // Report that we are scanning for web vulnerabilities
    bar.set_message(starter.clone());

    let full_location = format!("{protocol}://{}:{port}", args_bundle.machine().web_target());

    // Run the vuln scan and capture the output
    let args = vec!["-host", &full_location, "-maxtime", "60"];
    let command = imd::get_command_output("nikto", args)?;

    // Create a file for the results
    let output_file = format!("{}/web_vulns_port_{port}", ip_string);
    let mut f = imd::create_file(args_bundle.user(), &output_file)?;

    // Write the command output to the file
    writeln!(f, "{command}")?;

    // Report that we completed the web vuln scan
    let output = imd::report(&imd::IMDOutcome::Good, "Done");
    bar.finish_with_message(format!("{starter}{output}"));

    Ok(())
}

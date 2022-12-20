use indicatif::MultiProgress;
use std::error::Error;
use std::io::Write;
use std::sync::Arc;

pub fn dir_and_file_scan(
    bar_container: Arc<MultiProgress>,
    user: Arc<imd::IMDUser>,
    ip_address: &str,
    protocol: &str,
    port: &str,
    web_location: &str,
    wordlist: &str,
) -> Result<(), Box<dyn Error>> {
    // Create a bar for messaging progress
    let bar = bar_container.add(imd::make_new_bar());

    // All messages logged will start with the same thing so create it once up front
    let starter = imd::make_message_starter(ip_address, &format!("Scanning for web directories and files on port {port} with 'feroxbuster -q --thorough --time-limit 10m'"));
    let starter_clone = starter.clone();

    // Report that we are scanning for web directories and files
    bar.set_message(starter);

    let full_location = format!("{protocol}://{web_location}:{port}");

    // Run the vuln scan and capture the output
    let args = vec!["-q", "--thorough", "--time-limit", "10m", "--no-state", "-w", wordlist, "-u", &full_location];
    let command = imd::get_command_output("feroxbuster", args)?;

    // For some reason this output has double "\n" at the end of each line, so we fix that
    let command = command.replace("\n\n", "\n");

    // Create a file for the results
    let output_file = format!("{ip_address}/web_dirs_and_files_port_{port}");
    let mut f = imd::create_file(user, &output_file)?;

    // Write the command output to the file
    writeln!(f, "{command}")?;

    // Report that we were successful in adding to /etc/hosts
    let output = imd::report(imd::IMDOutcome::Good, "Done");
    bar.finish_with_message(format!("{starter_clone}{output}"));

    Ok(())
}

pub fn vuln_scan(
    bar_container: Arc<MultiProgress>,
    user: Arc<imd::IMDUser>,
    ip_address: &str,
    protocol: &str,
    port: &str,
    web_location: &str,
) -> Result<(), Box<dyn Error>> {
    // Create a bar for messaging progress
    let bar = bar_container.add(imd::make_new_bar());

    // All messages logged will start with the same thing so create it once up front
    let starter = imd::make_message_starter(
        ip_address,
        &format!("Scanning for web vulnerabilities on port {port} with 'nikto -host -maxtime 60'"),
    );
    let starter_clone = starter.clone();

    // Report that we are scanning for web vulnerabilities
    bar.set_message(starter);

    let full_location = format!("{protocol}://{web_location}:{port}");

    // Run the vuln scan and capture the output
    let args = vec!["-host", &full_location, "-maxtime", "60"];
    let command = imd::get_command_output("nikto", args)?;

    // Create a file for the results
    let output_file = format!("{ip_address}/web_vulns_port_{port}");
    let mut f = imd::create_file(user, &output_file)?;

    // Write the command output to the file
    writeln!(f, "{command}")?;

    // Report that we completed the web vuln scan
    let output = imd::report(imd::IMDOutcome::Good, "Done");
    bar.finish_with_message(format!("{starter_clone}{output}"));

    Ok(())
}

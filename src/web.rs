use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::error::Error;
use std::io::Write;
use std::sync::Arc;


pub fn dir_and_file_scan(user: Arc<imd::IMDUser>, ip_address: &str, protocol: &str, port: &str, web_location: &str, wordlist: &str, bar_container: Arc<MultiProgress>, bar_style: ProgressStyle) -> Result<(), Box<dyn Error>> {
    // Create a bar for messaging progress
    let bar = bar_container.add(ProgressBar::new(0).with_style(bar_style));
    
    // Report that we are scanning for web vulnerabilities
    bar.set_message(format!("{}{}", imd::format_ip_address(ip_address), &format!("Scanning for web directories and files on port {port} with 'feroxbuster -q --thorough'")));


    let full_location = format!("{protocol}://{web_location}:{port}");

    // Run the vuln scan and capture the output
    let args = vec!["-q", "--thorough", "-w", wordlist, "-u", &full_location];
    let command = imd::get_command_output("feroxbuster", args)?;

    // For some reason this output has double "\n" at the end of each line, so we fix that
    let command = command.replace("\n\n", "\n");

    // Create a file for the results
    let output_filename = format!("{ip_address}/web_dirs_and_files_port_{port}");
    let mut f = imd::create_file(user, &output_filename)?;

    // Write the command output to the file
    writeln!(f, "{command}")?;

    // Report that we were successful in adding to /etc/hosts
    bar.finish_with_message(format!("{}{} {}", imd::format_ip_address(ip_address), &format!("Scanning for web directories and files on port {port} with 'feroxbuster -q --thorough'"), imd::color_text("✔️ Done", Some(imd::Color::Green))));

    Ok(())
}


pub fn vuln_scan(user: Arc<imd::IMDUser>, ip_address: &str, protocol: &str, port: &str, web_location: &str, bar_container: Arc<MultiProgress>, bar_style: ProgressStyle) -> Result<(), Box<dyn Error>> {
    // Create a bar for messaging progress
    let bar = bar_container.add(ProgressBar::new(0).with_style(bar_style));
    
    // Report that we are scanning for web vulnerabilities
    bar.set_message(format!("{}{}", imd::format_ip_address(ip_address), &format!("Scanning for web vulnerabilities on port {port} with 'nikto -host'")));

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
    bar.finish_with_message(format!("{}{} {}", imd::format_ip_address(ip_address), &format!("Scanning for web vulnerabilities on port {port} with 'nikto -host'"), imd::color_text("✔️ Done", Some(imd::Color::Green))));

    Ok(())
}

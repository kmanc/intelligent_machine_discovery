use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::error::Error;
use std::io::Write;
use std::sync::Arc;


pub fn network_drives(user: Arc<imd::IMDUser>, ip_address: &str, bar_container: Arc<MultiProgress>, bar_style: ProgressStyle) -> Result<(), Box<dyn Error>> {
    // Create a bar for messaging progress
    let bar = bar_container.add(ProgressBar::new(0).with_style(bar_style));
    
    // Report that we are adding the machine to /etc/hosts
    bar.set_message(format!("{}{}", imd::format_ip_address(ip_address), "Scanning for network drives using 'showmount -e'"));

    // Run the showmount command and capture the output
    let args = vec!["-e", ip_address];
    let command = imd::get_command_output("showmount", args)?;

    // Create a file for the results
    let output_filename = format!("{ip_address}/nfs_shares");
    let mut f = imd::create_file(user, &output_filename)?;

    // Write the command output to the file
    writeln!(f, "{command}")?;

    // Report that we completed the network drive scan
    // Report that we were successful in adding to /etc/hosts
    bar.finish_with_message(format!("{}{} {}", imd::format_ip_address(ip_address), "Scanning for network drives using 'showmount -e'", imd::color_text("✔️ Done", Some(imd::Color::Green))));

    Ok(())

}

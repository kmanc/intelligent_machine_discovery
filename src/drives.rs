use std::error::Error;
use std::io::Write;
use std::sync::{Arc, mpsc};


pub fn network_drives(tx: mpsc::Sender<String>, user: Arc<imd::IMDUser>, ip_address: &str) -> Result<(), Box<dyn Error>> {
    // Report that we are scanning network drives
    let log = imd::format_log(ip_address, "Scanning for network drives using 'showmount -e'", None);
    tx.send(log)?;

    // Run the showmount command and capture the output
    let args = vec!["-e", ip_address];
    let command = imd::get_command_output("showmount", args)?;

    // Create a file for the results
    let output_filename = format!("{ip_address}/nfs_shares");
    let mut f = imd::create_file(user, &output_filename)?;

    // Write the command output to the file
    writeln!(f, "{command}")?;

    // Report that we completed the network drive scan
    let log = imd::format_log(ip_address, "Network drive scan complete", Some(imd::Color::Green));
    tx.send(log)?;

    Ok(())

}

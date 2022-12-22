use std::error::Error;
use std::io::Write;
use std::sync::Arc;

pub fn network_drives(args_bundle: &Arc<imd::DiscoveryArgs>) -> Result<(), Box<dyn Error>> {
    // Create a bar for messaging progress
    let bar = args_bundle.bars_container().add(imd::make_new_bar());

    // Prevent borrow-after-freed
    let ip_string = &args_bundle.machine().ip_address().to_string();

    // All messages logged will start with the same thing so create it once up front
    let starter = imd::make_message_starter(
        ip_string,
        "Scanning for network drives using 'showmount -e'",
    );

    // Report that we are scanning for NFS shares
    bar.set_message(starter.clone());

    // Run the showmount command and capture the output
    let args = vec!["-e", ip_string];
    let command = imd::get_command_output("showmount", args)?;

    // Create a file for the results
    let output_file = format!("{}/nfs_shares", ip_string);
    let mut f = imd::create_file(args_bundle.user(), &output_file)?;

    // Write the command output to the file
    writeln!(f, "{command}")?;

    // Report that we completed the network drive scan
    let output = imd::report(&imd::IMDOutcome::Good, "Done");
    bar.finish_with_message(format!("{starter}{output}"));

    Ok(())
}

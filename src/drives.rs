use indicatif::MultiProgress;
use std::error::Error;
use std::io::Write;
use std::sync::Arc;

pub fn network_drives(
    bar_container: Arc<MultiProgress>,
    user: Arc<imd::IMDUser>,
    ip_address: &str,
) -> Result<(), Box<dyn Error>> {
    // Create a bar for messaging progress
    let bar = bar_container.add(imd::make_new_bar());

    // All messages logged will start with the same thing so create it once up front
    let starter = imd::make_message_starter(
        ip_address,
        "Scanning for network drives using 'showmount -e'",
    );
    let starter_clone = starter.clone();

    // Report that we are scanning for NFS shares
    bar.set_message(starter);

    // Run the showmount command and capture the output
    let args = vec!["-e", ip_address];
    let command = imd::get_command_output("showmount", args)?;

    // Create a file for the results
    let output_file = format!("{ip_address}/nfs_shares");
    let mut f = imd::create_file(user, &output_file)?;

    // Write the command output to the file
    writeln!(f, "{command}")?;

    // Report that we completed the network drive scan
    // Report that we were successful in adding to /etc/hosts
    let output = imd::report_good("Done");
    bar.finish_with_message(format!("{starter_clone}{output}"));

    Ok(())
}

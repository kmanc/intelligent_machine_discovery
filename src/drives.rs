use std::io::Write;
use std::sync::Arc;

pub fn network_drives(args_bundle: &Arc<imd::DiscoveryArgs>) {
    // Add a bar for messaging progress
    let bar = args_bundle.add_new_bar();

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
    let command = match imd::get_command_output("showmount", args) {
        Err(_) => {
            let output = imd::report(
                &imd::IMDOutcome::Bad,
                "Problem running the showmount command",
            );
            bar.finish_with_message(format!("{starter}{output}"));
            return;
        }
        Ok(command) => command,
    };

    // Create a file for the results
    let output_file = format!("{ip_string}/nfs_shares");
    let mut f = match imd::create_file(args_bundle.user(), &output_file) {
        Err(_) => {
            let output = imd::report(
                &imd::IMDOutcome::Bad,
                "Problem creating file for the output of the showmount command",
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
            "Problem writing the results of the showmount command",
        );
        bar.finish_with_message(format!("{starter}{output}"));
        return;
    };

    // Report that we completed the network drive scan
    let output = imd::report(&imd::IMDOutcome::Good, "Done");
    bar.finish_with_message(format!("{starter}{output}"));
}

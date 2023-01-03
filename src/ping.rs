use std::sync::Arc;

pub fn verify_connection(args_bundle: &Arc<imd::DiscoveryArgs>) -> imd::IMDOutcome {
    // Add a bar for messaging progress
    let bar = args_bundle.add_new_bar();

    // Prevent borrow-after-freed
    let ip_string = &args_bundle.machine().ip_address().to_string();

    // All messages logged will start with the same thing so create it once up front
    let starter = imd::format_command_start(ip_string, 16, "Verifying connectivity");

    // Report that we are verifying connectivity
    bar.set_message(starter.clone());

    // Run the ping command and capture the output
    let args = vec!["-c", "4", ip_string];
    let command = match imd::get_command_output("ping", args, &bar, &starter) {
        Err(_) => return imd::IMDOutcome::Bad,
        Ok(command) => command,
    };

    if command.contains("100% packet loss") || command.contains("100.0% packet loss") {
        let output =
            imd::format_command_result(&imd::IMDOutcome::Bad, "Machine could not be reached");
        bar.finish_with_message(format!("{starter}{output}"));
        return imd::IMDOutcome::Bad;
    }

    // Report that we were successful in verifying the connection
    let output = imd::format_command_result(&imd::IMDOutcome::Good, "Done");
    bar.finish_with_message(format!("{starter}{output}"));

    imd::IMDOutcome::Good
}

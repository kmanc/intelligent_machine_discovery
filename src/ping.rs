use std::sync::Arc;

pub fn verify_connection(args_bundle: &Arc<imd::DiscoveryArgs>) -> imd::PingResult {
    // Add a bar for messaging progress
    let bar = args_bundle.add_new_bar();

    // Prevent borrow-after-freed
    let ip_string = &args_bundle.machine().ip_address().to_string();

    // All messages logged will start with the same thing so create it once up front
    let starter = imd::make_message_starter(ip_string, "Verifying connectivity");

    // Report that we are verifying connectivity
    bar.set_message(starter.clone());

    // Run the ping command and capture the output
    let args = vec!["-c", "4", ip_string];
    let command = match imd::get_command_output("ping", args) {
        Err(_) => {
            let output = imd::report(&imd::IMDOutcome::Bad, "Problem running ping command");
            bar.finish_with_message(format!("{starter}{output}"));
            return imd::PingResult::Bad;
        }
        Ok(command) => command,
    };

    if command.contains("100% packet loss") || command.contains("100.0% packet loss") {
        let output = imd::report(&imd::IMDOutcome::Bad, "Machine could not be reached");
        bar.finish_with_message(format!("{starter}{output}"));
        return imd::PingResult::Bad;
    }

    // Report that we were successful in verifying the connection
    let output = imd::report(&imd::IMDOutcome::Good, "Done");
    bar.finish_with_message(format!("{starter}{output}"));

    imd::PingResult::Good
}

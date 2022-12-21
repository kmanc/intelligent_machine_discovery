use std::error::Error;
use std::sync::Arc;

pub fn verify_connection(
    args_bundle: &Arc<imd::DiscoveryArgs>,
) -> Result<imd::PingResult, Box<dyn Error>> {
    // Create a bar for messaging progress
    let bar = args_bundle.bars_container().add(imd::make_new_bar());

    // All messages logged will start with the same thing so create it once up front
    let starter = imd::make_message_starter(args_bundle.ip_address(), "Verifying connectivity");
    let starter_clone = starter.clone();

    // Report that we are verifying connectivity
    bar.set_message(starter);

    // Run the ping command and capture the output
    let args = vec!["-c", "4", args_bundle.ip_address()];
    let command = imd::get_command_output("ping", args)?;

    if command.contains("100% packet loss") || command.contains("100.0% packet loss") {
        let output = imd::report(&imd::IMDOutcome::Bad, "Machine could not be reached");
        bar.finish_with_message(format!("{starter_clone}{output}"));
        return Ok(imd::PingResult::Bad);
    }

    // Report that we were successful in verifying the connection
    let output = imd::report(&imd::IMDOutcome::Good, "Done");
    bar.finish_with_message(format!("{starter_clone}{output}"));

    Ok(imd::PingResult::Good)
}

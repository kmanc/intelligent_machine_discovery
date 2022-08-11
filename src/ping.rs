use std::error::Error;
use std::fmt;
use std::sync::mpsc;


#[derive(Clone, Debug)]
struct ConnectionError;


impl Error for ConnectionError {}


impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "The target machine could not be reached")
    }
}


pub fn verify_connection(tx: mpsc::Sender<String>, ip_address: &str) -> Result<(), Box<dyn Error>> {
    // Report that we are verifying connectivity
    let log = imd::format_log(ip_address, "Verifying connectivity");
    tx.send(log)?;
    
    // Run the ping command and capture the output
    let args = vec!["-c", "-6", ip_address];
    let command = imd::get_command_output("ping", args)?;

    if command.contains("100% packet loss") || command.contains("100.0% packet loss") {
        return Err(Box::new(ConnectionError))
    }

    // Report that we were successful in verifying the connection
    let log = imd::format_log(ip_address, "Connection confirmed");
    tx.send(log)?;

    Ok(())
}

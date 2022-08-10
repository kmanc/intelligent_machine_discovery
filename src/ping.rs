use std::error::Error;
use std::fmt;
use std::process::Command;
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
    let ping = Command::new("ping").arg("-c")
                                   .arg("8")
                                   .arg(ip_address)
                                   .output()?;
    let ping = String::from_utf8(ping.stdout)?;

    if ping.contains("100% packet loss") || ping.contains("100.0% packet loss") {
        return Err(Box::new(ConnectionError))
    }

    // Report that we were successful in verifying the connection
    let log = imd::format_log(ip_address, "Connection confirmed");
    tx.send(log)?;

    Ok(())
}

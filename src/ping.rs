use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::error::Error;
use std::fmt;
use std::sync::Arc;


#[derive(Debug)]
struct ConnectionError;


impl Error for ConnectionError {}


impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "The target machine could not be reached")
    }
}


pub fn verify_connection(ip_address: &str, bar_container: Arc<MultiProgress>, bar_style: ProgressStyle) -> Result<imd::PingResult, Box<dyn Error>> {
    // Create a bar for messaging progress
    let bar = bar_container.add(ProgressBar::new(0).with_style(bar_style));
    
    // Report that we are verifying connectivity
    bar.set_message(format!("{}{}", imd::format_ip_address(ip_address), "Verifying connectivity"));
    
    // Run the ping command and capture the output
    let args = vec!["-c", "4", ip_address];
    let command = imd::get_command_output("ping", args)?;

    if command.contains("100% packet loss") || command.contains("100.0% packet loss") {
        bar.finish_with_message(format!("{}{} {}", imd::format_ip_address(ip_address), "Verifying connectivity", imd::color_text("x Machine could not be reached", Some(imd::Color::Red))));
        return Ok(imd::PingResult::Bad)
    }

    // Report that we were successful in verifying the connection
    bar.finish_with_message(format!("{}{} {}", imd::format_ip_address(ip_address), "Verifying connectivity", imd::color_text("✔️ Done", Some(imd::Color::Green))));
    
    Ok(imd::PingResult::Good)
}

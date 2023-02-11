use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::sync::Arc;

pub fn parse_port_scan(
    args_bundle: &Arc<imd::DiscoveryArgs>,
    port_scan: &str,
) -> HashMap<String, Vec<String>> {
    // Add a bar for messaging progress
    let bar = imd::add_new_bar(args_bundle.bars_container());

    // Prevent borrow-after-freed
    let ip_string = &args_bundle.machine().ip_address().to_string();

    // All messages logged will start with the same thing so create it once up front
    let starter =
        imd::format_command_start(ip_string, 16, "Parsing port scan to determine next steps");

    // Report that we are parsing the port scan
    bar.set_message(starter.clone());

    // Prep the scan string for searching by splitting it to a vector of lines, trimming each line, and removing lines that start with "|" or "SF:"
    let port_scan: Vec<String> = port_scan
        .split('\n')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.starts_with('|'))
        .filter(|s| !s.starts_with("SF:"))
        .collect();

    // Define a list of services that we will do something about
    let services = vec!["http", "ssl/http"];

    // Create a new HashMap to store results in
    let mut services_map: HashMap<String, Vec<String>> = HashMap::new();

    // Iterate over the port scan and find ports that host services we are looking for. Add those service / port pairs to the map
    for line in port_scan {
        for service in &services {
            if line.contains(service) && line.contains("open") {
                let port = line.split('/').collect::<Vec<&str>>()[0];
                let service = match service {
                    &"ssl/http" => "https",
                    _ => service,
                };
                services_map
                    .entry(service.to_string())
                    .or_default()
                    .push(port.to_string());
            }
        }
    }

    // Report that we were successful in parsing the port scan
    let output = imd::format_command_result(&imd::IMDOutcome::Good, "Done");
    bar.finish_with_message(format!("{starter}{output}"));

    services_map
}

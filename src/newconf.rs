use clap::{Arg, Command}; // 4.0.32
use std::net::IpAddr;


struct TargetMachine<'a> {
    ip_address: IpAddr,
    hostname: Option<&'a str>,
}

impl TargetMachine<'_> {
    pub fn new(input: String) -> TargetMachine<'static> {
        let parts = input.split_once('=').unwrap();
        let ip_address = parts.0.parse::<IpAddr>().unwrap();
        let hostname = (!parts.1.is_empty()).then(|| parts.1);
        if parts.1.is_empty() {
            return TargetMachine {ip_address, hostname}
        } else {
            return TargetMachine {ip_address, hostname}
        }
    }
}

fn main() -> () {
    let app = cli();
    let matches = app.get_matches();
}

fn cli() -> Command {
    let app = clap::Command::new("crate_name");
    app.arg(
        Arg::new("targets")
            .short('t')
            .num_args(1..)
            .required(true)
    )
}

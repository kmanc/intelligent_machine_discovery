pub mod error;
use crossterm::style::Stylize;
use error::{PanicDiscoveryError, RecoverableDiscoveryError};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use nix::unistd::{self, Gid, Uid, User};
use std::collections::HashMap;
use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

const SUCCESS: &str = "✔️ Done";

#[derive(Clone)]
pub struct CLITarget {
    hostname: Option<String>,
    ip_address: IpAddr,
}

impl CLITarget {
    // Parse a CLITarget from the command line arguments
    pub fn new(input: &str) -> Result<CLITarget, PanicDiscoveryError> {
        if let Some(parts) = input.split_once('=') {
            Ok(CLITarget {
                hostname: Some(parts.1.to_string()),
                ip_address: wrap_ip_address_parse(parts.0)?,
            })
        } else {
            Ok(CLITarget {
                hostname: None,
                ip_address: wrap_ip_address_parse(input)?,
            })
        }
    }

    // Generate the progress prefix for a target machine
    fn create_prefix(&self, total_len: usize) -> String {
        format!(
            "{ip_address: <total_len$} -",
            ip_address = self.ip_address,
            total_len = total_len,
        )
    }

    // Clippy complains if I don't do this
    pub fn is_empty(&self) -> bool {
        false
    }

    // Get the length of the CLITarget's IP address
    pub fn len(&self) -> usize {
        self.ip_address.to_string().len()
    }
}

#[derive(Clone, Debug)]
pub struct IMDUser {
    gid: Gid,
    name: String,
    uid: Uid,
}

impl IMDUser {
    pub fn new(gid: Gid, name: String, uid: Uid) -> IMDUser {
        IMDUser { gid, name, uid }
    }

    pub fn gid(&self) -> &Gid {
        &self.gid
    }

    pub fn name(&self) -> &String {
        &self.name
    }

    pub fn uid(&self) -> &Uid {
        &self.uid
    }
}

#[derive(Clone, Debug)]
pub struct TargetMachine {
    hostname: Option<String>,
    ip_address: IpAddr,
    mp: Arc<MultiProgress>,
    prefix: String,
}

impl TargetMachine {
    // Create a target machine from the CLITarget object and a few other bits that don't come from the command line
    pub fn new(cli: CLITarget, prefix_size: usize, mp: Arc<MultiProgress>) -> TargetMachine {
        let prefix = cli.create_prefix(prefix_size);
        TargetMachine {
            hostname: cli.hostname,
            ip_address: cli.ip_address,
            mp,
            prefix,
        }
    }

    // Add hostname the /etc/hosts file if there is in fact a hostname to add
    fn add_to_hosts(&self, ip_string: &str) -> Result<(), Box<dyn Error>> {
        let hostname = match &self.hostname {
            Some(hostname) => hostname,
            None => return Ok(()),
        };
        let bar = add_new_bar(self.mp());
        let message = self.prefix.clone() + " Adding to /etc/hosts";
        bar.set_message(message.clone());

        let host_file = File::open("/etc/hosts")?;
        let reader = BufReader::new(host_file);
        for line in reader.lines() {
            let line = line?;
            // If a line contains the ip address and hostname already, let the user know it is already there and exit
            if line.contains(ip_string) && line.contains(hostname) {
                bar.finish_with_message(format!(
                    "{} {}",
                    message,
                    RecoverableDiscoveryError::AlreadyInHost
                ));
                return Ok(());
            }
        }

        // If we didn't already return, add the entry to the /etc/hosts file because it wasn't there
        let host_file = OpenOptions::new().append(true).open("/etc/hosts")?;

        writeln!(&host_file, "{ip_string} {hostname}")?;
        let message = format!("{message} {}", SUCCESS.green());
        bar.finish_with_message(message);

        Ok(())
    }

    // Create a directory owned by the provided user
    pub fn create_results_dir(
        &self,
        dir_name: &str,
        user: Arc<IMDUser>,
    ) -> Result<(), Box<dyn Error>> {
        let bar = add_new_bar(self.mp());
        let message = self.prefix.clone() + " Creating directory to store results in";
        bar.set_message(message.clone());

        // If it fails, it's probably because the directory already exists (not 100%, but pretty likely), so report that and move on
        if fs::create_dir(dir_name).is_err() {
            bar.finish_with_message(format!(
                "{} {}",
                message,
                RecoverableDiscoveryError::DirectoryExists
            ));
            return Ok(());
        }

        change_owner(dir_name, user)?;

        let message = format!("{message} {}", SUCCESS.green());
        bar.finish_with_message(message);

        Ok(())
    }

    // Catchall method for running discovery on a target machine
    pub fn discovery(&self, user: Arc<IMDUser>, wordlist: Arc<String>) {
        let ip_string = self.ip_as_string();
        if self.ping(&ip_string).is_err() {
            return;
        }
        if self.add_to_hosts(&ip_string).is_err() {}
        if self.create_results_dir(&ip_string, user.clone()).is_err() {
            return;
        }

        let mut threads: Vec<std::thread::JoinHandle<()>> = vec![];

        threads.push(std::thread::spawn({
            let clone = self.clone();
            let ip_string = ip_string.clone();
            let user = user.clone();
            move || {
                if clone.nmap_all_tcp_ports(&ip_string, user).is_err() {}
            }
        }));

        threads.push(std::thread::spawn({
            let clone = self.clone();
            let ip_string = ip_string.clone();
            let user = user.clone();
            move || {
                if clone.showmount_network_drives(&ip_string, user).is_err() {}
            }
        }));

        let port_scan = match self.nmap_common_tcp_ports(&ip_string, user.clone()) {
            Ok(port_scan) => port_scan,
            Err(_) => return,
        };

        let services = Arc::new(self.parse_port_scan(port_scan));

        for (service, ports) in services.iter() {
            for port in ports {
                // Spin up a thread for the vuln scan
                threads.push(std::thread::spawn({
                    let clone = self.clone();
                    let ip_string = ip_string.clone();
                    let port = port.clone();
                    let service = service.clone();
                    let user = user.clone();
                    move || {
                        if clone.vuln_scan(&ip_string, user, &service, &port).is_err() {}
                    }
                }));
                // Spin up a thread for the web dir and file scanning
                threads.push(std::thread::spawn({
                    let clone = self.clone();
                    let ip_string = ip_string.clone();
                    let port = port.clone();
                    let service = service.clone();
                    let user = user.clone();
                    let wordlist = wordlist.clone();
                    move || {
                        if clone
                            .web_presence_scan(&ip_string, user, &service, &port, &wordlist)
                            .is_err()
                        {}
                    }
                }));
            }
        }

        for thread in threads {
            thread.join().unwrap();
        }
    }

    // Return the IP address as a string
    fn ip_as_string(&self) -> String {
        self.ip_address.to_string()
    }

    // Return a clone of the MultiProgress container
    fn mp(&self) -> Arc<MultiProgress> {
        self.mp.clone()
    }

    // Discover open TCP ports
    fn nmap_all_tcp_ports(
        &self,
        ip_string: &str,
        user: Arc<IMDUser>,
    ) -> Result<(), Box<dyn Error>> {
        let bar = add_new_bar(self.mp());
        let message = self.prefix.clone() + " Scanning all TCP ports: 'nmap -p- -Pn'";
        bar.set_message(message.clone());

        let args = vec!["-p-", "-Pn", ip_string];
        let command = run_command_with_args("nmap", args)?;

        let output_file = format!("{ip_string}/all_tcp_ports");
        let mut f = create_file(&output_file, user)?;
        writeln!(f, "{command}")?;

        let message = format!("{message} {}", SUCCESS.green());
        bar.finish_with_message(message);

        Ok(())
    }

    // Discover (with service information) common open TCP ports
    fn nmap_common_tcp_ports(
        &self,
        ip_string: &str,
        user: Arc<IMDUser>,
    ) -> Result<String, Box<dyn Error>> {
        let bar = add_new_bar(self.mp());
        let message = self.prefix.clone()
            + " Scanning common TCP ports: 'nmap -sV -Pn --script (a few useful scripts)'";
        bar.set_message(message.clone());

        let args = vec![
            "-sV",
            "-Pn",
            "--script",
            "http-robots.txt",
            "--script",
            "http-title",
            "--script",
            "ssl-cert",
            "--script",
            "ftp-anon",
            ip_string,
        ];
        let command = run_command_with_args("nmap", args)?;

        let output_file = format!("{ip_string}/common_tcp_ports");
        let mut f = create_file(&output_file, user)?;
        writeln!(f, "{command}")?;

        let message = format!("{message} {}", SUCCESS.green());
        bar.finish_with_message(message);

        Ok(command)
    }

    // Parse out the services from the nmap -sV scan
    pub fn parse_port_scan(&self, port_scan: String) -> HashMap<String, Vec<String>> {
        let bar = add_new_bar(self.mp());
        let message = self.prefix.clone() + " Parsing port scan";
        bar.set_message(message.clone());

        // Prep the scan string for searching by splitting it to a vector of lines, trimming each line, and removing lines that start with "|" or "SF:"
        let port_scan: Vec<String> = port_scan
            .split('\n')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.starts_with('|'))
            .filter(|s| !s.starts_with("SF:"))
            .collect();

        // Define a list of services that we will do something about
        let services = vec!["http", "ssl/http"];
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

        let message = format!("{message} {}", SUCCESS.green());
        bar.finish_with_message(message);

        services_map
    }

    // Confirm the target machine is reachable via ping
    fn ping(&self, ip_string: &str) -> Result<(), RecoverableDiscoveryError> {
        let bar = add_new_bar(self.mp());
        let message = self.prefix.clone() + " Verifying connectivity";
        bar.set_message(message.clone());

        let args = vec!["-c", "4", ip_string];
        match run_command_with_args("ping", args) {
            Err(_) => return Err(RecoverableDiscoveryError::Connection),
            Ok(ping) => {
                if ping.contains("100% packet loss") || ping.contains("100.0% packet loss") {
                    bar.finish_with_message(format!(
                        "{} {}",
                        message,
                        RecoverableDiscoveryError::Connection
                    ));
                    return Err(RecoverableDiscoveryError::Connection);
                }
            }
        }

        let message = format!("{message} {}", SUCCESS.green());
        bar.finish_with_message(message);
        Ok(())
    }

    // Discover network drives
    fn showmount_network_drives(
        &self,
        ip_string: &str,
        user: Arc<IMDUser>,
    ) -> Result<(), Box<dyn Error>> {
        let bar = add_new_bar(self.mp());
        let message = self.prefix.clone() + " Scanning network drives: 'showmount -e'";
        bar.set_message(message.clone());

        let args = vec!["-e", ip_string];
        let command = run_command_with_args("showmount", args)?;
        let output_file = format!("{ip_string}/nfs_shares");
        let mut f = create_file(&output_file, user)?;
        writeln!(f, "{command}")?;

        let message = format!("{message} {}", SUCCESS.green());
        bar.finish_with_message(message);

        Ok(())
    }

    // Discover web dirs and files
    pub fn web_presence_scan(
        &self,
        ip_string: &str,
        user: Arc<IMDUser>,
        protocol: &str,
        port: &str,
        wordlist: &str,
    ) -> Result<(), Box<dyn Error>> {
        let bar = add_new_bar(self.mp());
        let message = self.prefix.clone()
            + &format!(" Scanning web presence on port {port}: 'feroxbuster -q --thorough --time-limit 10m'");
        bar.set_message(message.clone());

        let web_target = self.web_target();
        let full_target = format!("{protocol}://{web_target}:{port}");

        let args = vec![
            "-q",
            "--thorough",
            "--time-limit",
            "10m",
            "--no-state",
            "-w",
            wordlist,
            "-u",
            &full_target,
        ];
        let command = run_command_with_args("feroxbuster", args)?;
        let command = command.replace("\n\n", "\n");

        let output_file = format!("{ip_string}/web_dirs_and_files_port_{port}");
        let mut f = create_file(&output_file, user)?;
        writeln!(f, "{command}")?;

        let message = format!("{message} {}", SUCCESS.green());
        bar.finish_with_message(message);

        Ok(())
    }

    // Return the hostname if it exists, or the IP address as a string if not
    fn web_target(&self) -> String {
        match &self.hostname {
            Some(hostname) => hostname.to_string(),
            None => self.ip_as_string(),
        }
    }

    // Check for common web vulnerabilities or misconfigurations
    fn vuln_scan(
        &self,
        ip_string: &str,
        user: Arc<IMDUser>,
        protocol: &str,
        port: &str,
    ) -> Result<(), Box<dyn Error>> {
        let bar = add_new_bar(self.mp());
        let message = self.prefix.clone()
            + &format!(" Scanning web vulns on port {port}: 'nikto -host -maxtime 60'");
        bar.set_message(message.clone());

        let web_target = self.web_target();
        let full_target = format!("{protocol}://{web_target}:{port}");

        let args = vec!["-host", &full_target, "-maxtime", "60"];
        let command = run_command_with_args("nikto", args)?;

        let output_file = format!("{ip_string}/web_vulns_port_{port}");
        let mut f = create_file(&output_file, user)?;
        writeln!(f, "{command}")?;

        let message = format!("{message} {}", SUCCESS.green());
        bar.finish_with_message(message);

        Ok(())
    }
}

// Add a bar to the MultiProgress so it can be printed to
pub fn add_new_bar(mp: Arc<MultiProgress>) -> ProgressBar {
    let bar = mp.add(ProgressBar::new(0));
    let style = ProgressStyle::with_template("{msg}").unwrap();
    bar.set_style(style);
    bar
}

// Change the owner of the object to the provided user
pub fn change_owner(object: &str, new_owner: Arc<IMDUser>) -> Result<(), Box<dyn Error>> {
    unistd::chown(object, Some(*new_owner.uid()), Some(*new_owner.gid()))?;
    Ok(())
}

// Create a file owned by the provided to store the results of a command
pub fn create_file(filename: &str, user: Arc<IMDUser>) -> Result<File, Box<dyn Error>> {
    let f = File::create(filename)?;
    change_owner(filename, user)?;

    Ok(f)
}

// Get the effective user (which needs to be root for imd to work properly)
pub fn effective_user() -> Result<(), PanicDiscoveryError> {
    if !Uid::effective().is_root() {
        return Err(PanicDiscoveryError::NotRunAsRoot);
    }
    Ok(())
}

// Get the logged in user (hopefully the person who ran imd)
pub fn real_user() -> Result<IMDUser, Box<dyn Error>> {
    let name = Command::new("who").output()?;
    let name = String::from_utf8(name.stdout)?;
    let name = String::from(name.split(' ').collect::<Vec<&str>>()[0]);

    let (uid, gid) = match User::from_name(&name)? {
        Some(user) => (user.uid, user.gid),
        _ => (Uid::from_raw(0), Gid::from_raw(0)),
    };

    Ok(IMDUser::new(gid, name, uid))
}

// Convenience function to run a shell command with its arguments / flags and return the result as a string
pub fn run_command_with_args(command: &str, args: Vec<&str>) -> Result<String, Box<dyn Error>> {
    let out = Command::new(command).args(args).output()?;

    Ok(String::from_utf8(out.stdout)?)
}

// Wrapper for parsing an IP address such that we can use it for CLI parsing
fn wrap_ip_address_parse(ip_address: &str) -> Result<IpAddr, PanicDiscoveryError> {
    match ip_address.parse::<IpAddr>() {
        Ok(ip_address) => Ok(ip_address),
        Err(_) => Err(PanicDiscoveryError::InvalidIPAddress),
    }
}

// Wrapper for parsing a wordlist file such that we can use it for CLI parsing
pub fn wrap_wordlist_parse(wordlist: &str) -> Result<String, PanicDiscoveryError> {
    if !Path::new(&wordlist).exists() {
        return Err(PanicDiscoveryError::InvalidWordlist);
    }
    Ok(wordlist.to_string())
}

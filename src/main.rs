mod conf;
mod drives;
mod ping;
mod ports;
mod utils;
mod web;
use crossterm::style::Stylize;
use indicatif::{MultiProgress, ProgressStyle};
use std::error::Error;
use std::sync::Arc;
use std::thread;


fn main() {
    // Parse command line arguments and proceed if successful
    match conf::Conf::init(){
        Ok(conf) => post_main(conf),
        Err(e) => println!("{}", e.to_string().red()),
    }
}


fn post_main(conf: conf::Conf) {
    // Create a multiprogress bar for housing all the individual bars
    let bar_container = Arc::new(MultiProgress::new());

    // Set a style template for bars to use
    let bar_style = ProgressStyle::with_template("{msg}").unwrap();

    // Create a vector for threads. Each will be responsible for one target machine, and will likely spawn its own threads
    let mut threads = vec![];

    // Run the discovery function on each of the target machines in its own thread
    for machine in conf.machines().iter() {
        let hostname = Arc::new(machine.hostname().to_owned());
        let ip_address = Arc::new(machine.ip_address().to_string());
        threads.push(
            thread::spawn({
                let bar_container = bar_container.clone();
                let bar_style = bar_style.clone();
                let hostname = hostname.clone();
                let ip_address = ip_address.clone();
                let user = conf.real_user().clone();
                let wordlist = conf.wordlist().clone();
                move || {
                    if discovery(user, ip_address.clone(), hostname, wordlist, bar_container, bar_style).is_err() {}
                }
            })        
        );
    }

    // Make sure that all threads have completed before continuing execution
    for thread in threads {
        thread.join().unwrap();
    }

    println!("Discovery completed for all target machines");
}


fn discovery(user: Arc<imd::IMDUser>, ip_address: Arc<String>, hostname: Arc<Option<String>>, wordlist: Arc<String>, bar_container: Arc<MultiProgress>, bar_style: ProgressStyle) -> Result<(), Box<dyn Error>> {
    // Make sure that the target machine is reachable
    match ping::verify_connection(&ip_address, bar_container.clone(), bar_style.clone()) {
        Err(_) => return Err("Connection".into()),
        Ok(imd::PingResult::Bad) => return Err("Connection".into()),
        Ok(imd::PingResult::Good) => {},
    }

    // If the target machine has a hostname, add it to the /etc/hosts file and set it as the target for future web scans (if applicable)
    // Otherwise skip the /etc/hosts file and use the IP address for web scans
    let web_location: Arc<String> = match &*hostname {
        Some(hostname) => {
            let hostname = Arc::new(hostname.to_string());
            utils::add_to_etc_hosts(&hostname, &ip_address, bar_container.clone(), bar_style.clone()).unwrap();
            hostname
        },
        None => ip_address.clone(),
    };

    // Create a landing space for all of the files that results will get written to
    utils::create_dir(user.clone(), &ip_address, bar_container.clone(), bar_style.clone())?;

    // Create a vector for threads. Each will be responsible a sub-task run against the target machine
    let mut threads = vec![];

    // Scan all TCP ports on the machine
    threads.push(
        thread::spawn({
            let bar_container = bar_container.clone();
            let bar_style = bar_style.clone();
            let ip_address = ip_address.clone();
            let user = user.clone();
            move || {
                if ports::all_tcp_ports(user, &ip_address, bar_container, bar_style).is_err() {}
            }
        })
    );

    // Scan NFS server on the machine
    threads.push(
        thread::spawn({
            let bar_container = bar_container.clone();
            let bar_style = bar_style.clone();
            let ip_address = ip_address.clone();
            let user = user.clone();
            move || {
                if drives::network_drives(user, &ip_address, bar_container, bar_style).is_err() {}
            }
        })
    );

    // This is a workaround for indicatif having issues with some bars being in threads and others not
    // Spin up a thread for the common TCP port scan and the parsing of the results; immediately join on it to block further execution till it's complete
    let services = thread::spawn({
        let bar_container = bar_container.clone();
        let bar_style = bar_style.clone();
        let ip_address = ip_address.clone();
        let user = user.clone();
        move || {
            let port_scan = ports::common_tcp_ports(user, &ip_address, bar_container.clone(), bar_style.clone()).unwrap();
            utils::parse_port_scan(&ip_address, &port_scan, bar_container, bar_style).unwrap()
        }
    }).join().unwrap();
    let services = Arc::new(services);

    // For now we are only parsing web servers, so scan them for vulnerabilities, directories, and files
    for (service, ports) in services.iter() {
        for port in ports {
            // Spin up a thread for the vuln scan
            threads.push(
                thread::spawn({
                    let bar_container = bar_container.clone();
                    let bar_style = bar_style.clone();
                    let ip_address = ip_address.clone();
                    let port = port.clone();
                    let service = service.clone();
                    let user = user.clone();
                    let web_location = web_location.clone();
                    move || {
                        if web::vuln_scan(user, &ip_address, &service, &port, &web_location, bar_container, bar_style).is_err() {}
                    }
                })
            );
            // Spin up a thread for the web dir and file scanning
            threads.push(
                thread::spawn({
                    let bar_container = bar_container.clone();
                    let bar_style = bar_style.clone();
                    let ip_address = ip_address.clone();
                    let port = port.clone();
                    let service = service.clone();
                    let user = user.clone();
                    let web_location = web_location.clone();
                    let wordlist = wordlist.clone();
                    move || {
                        if web::dir_and_file_scan(user, &ip_address, &service, &port, &web_location, &wordlist, bar_container, bar_style).is_err() {}
                    }
                })
            );
        }
    }

    // Make sure that all threads have completed before continuing execution
    for thread in threads {
        thread.join().unwrap();
    }

    Ok(())
}

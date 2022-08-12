mod conf;
mod drives;
mod ping;
mod ports;
mod utils;
mod web;
use std::error::Error;
use std::sync::{Arc, mpsc};
use std::thread;


fn main() {
    // Parse command line arguments and proceed if successful
    match conf::Conf::parse(){
        Ok(conf) => post_main(conf),
        Err(e) => eprintln!("{e}"),
    }
}


fn post_main(conf: conf::Conf) {
    // Create send / receive channels
    let (tx, rx) = mpsc::channel();

    // Create a vector for threads. Each will be responsible for one target machine, and will likely spawn its own threads
    let mut threads = vec![];

    // Run the discovery function on each of the target machines in its own thread
    for machine in conf.machines().iter() {
        let ip_address = Arc::new(machine.ip_address().to_string());
        let hostname = Arc::new(machine.hostname().to_owned());
        threads.push(
            thread::spawn({
                let tx = tx.clone();
                let user = conf.real_user().clone();
                let ip_address = ip_address.clone();
                let hostname = hostname.clone();
                move || {
                    if let Err(e) = discovery(tx.clone(), user, ip_address, hostname) {
                        tx.send(e.to_string()).unwrap();
                    }
                }
            })        
        );
    }

    // Drop the main function's transmitter or execution will never stop
    drop(tx);

    // Handle the receive channel messages
    for received in rx {
        println!("{received}");
    }

    // Make sure that all threads have completed before continuing execution
    for thread in threads {
        thread.join().unwrap();
    }

    println!("Discovery completed for all target machines");
}


fn discovery(tx: mpsc::Sender<String>, user: Arc<imd::IMDUser>, ip_address: Arc<String>, hostname: Arc<Option<String>>) -> Result<(), Box<dyn Error>> {
    // Make sure that the target machine is reachable
    if ping::verify_connection(&tx, &ip_address).is_err() {
        return Err(imd::format_log(&ip_address, "Target machine could not be reached").into())
    }

    // Create a landing space for all of the files that results will get written to
    utils::create_dir(&tx, user.clone(), &ip_address)?;

    // Create a vector for threads. Each will be responsible a sub-task run against the target machine
    let mut threads = vec![];

    // Scan all TCP ports on the machine
    threads.push(
        thread::spawn({
            let tx = tx.clone();
            let user = user.clone();
            let ip_address = ip_address.clone();
            move || {
                if let Err(e) =  ports::all_tcp_ports(tx.clone(), user, &ip_address) {
                    let log = imd::format_log(&ip_address, &e.to_string());
                    tx.send(log).unwrap();
                }
            }
        })
    );

    // Scan NFS server on the machine
    threads.push(
        thread::spawn({
            let tx = tx.clone();
            let user = user.clone();
            let ip_address = ip_address.clone();
            move || {
                if let Err(e) = drives::network_drives(tx.clone(), user, &ip_address) {
                    let log = imd::format_log(&ip_address, &e.to_string());
                    tx.send(log).unwrap();
                }
            }
        })
    );

    // Scan common TCP ports and perform service discovery
    let port_scan = ports::common_tcp_ports(&tx, user.clone(), &ip_address)?;

    // Parse the port scan to determine which services are running and where
    let services = utils::parse_port_scan(&tx, &ip_address, &port_scan)?;
    let services = Arc::new(services);

    // If the target machine has a hostname, add it to the /etc/hosts file and set it as the target for future web scans (if applicable). Otherwise use the IP address
    let web_location: Arc<String> = match &*hostname {
        Some(hostname) => {
            let hostname = Arc::new(hostname.to_string());
            utils::add_to_etc_hosts(&tx, &hostname, &ip_address).unwrap();
            hostname
        },
        None => ip_address.clone(),
    };

    // If an HTTP web server is present, scan for vulnerabilities, directories, and files
    for port in services.get("http").unwrap_or(&vec![]) {
        // Spin up a thread for the vuln scan
        threads.push(
            thread::spawn({
                let tx = tx.clone();
                let user = user.clone();
                let ip_address = ip_address.clone();
                let port = port.clone();
                let web_location = web_location.clone();
                move || {
                    if let Err(e) = web::vuln_scan(tx.clone(), user, &ip_address, "http", &port, &web_location) {
                        let log = imd::format_log(&ip_address, &e.to_string());
                        tx.send(log).unwrap();
                    }
                }
            })
        );
        // Spin up a thread for the web dir and file scanning
        threads.push(
            thread::spawn({
                let tx = tx.clone();
                let user = user.clone();
                let ip_address = ip_address.clone();
                let port = port.clone();
                let web_location = web_location.clone();
                move || {
                    if let Err(e) = web::dir_and_file_scan(tx.clone(), user, &ip_address, "http", &port, &web_location) {
                        let log = imd::format_log(&ip_address, &e.to_string());
                        tx.send(log).unwrap();
                    }
                }
            })
        );
    }

    // If an HTTPS web server is present, scan for vulnerabilities, directories, and files
    for port in services.get("ssl/http").unwrap_or(&vec![]) {
        // Spin up a thread for the vuln scan
        threads.push(
            thread::spawn({
                let tx = tx.clone();
                let user = user.clone();
                let ip_address = ip_address.clone();
                let port = port.clone();
                let web_location = web_location.clone();
                move || {
                    if let Err(e) = web::vuln_scan(tx.clone(), user, &ip_address, "http", &port, &web_location) {
                        let log = imd::format_log(&ip_address, &e.to_string());
                        tx.send(log).unwrap();
                    }
                }
            })
        );
        // Spin up a thread for the web dir and file scanning
        threads.push(
            thread::spawn({
                let tx = tx.clone();
                let user = user.clone();
                let ip_address = ip_address.clone();
                let port = port.clone();
                let web_location = web_location.clone();
                move || {
                    if let Err(e) = web::dir_and_file_scan(tx.clone(), user, &ip_address, "https", &port, &web_location) {
                        let log = imd::format_log(&ip_address, &e.to_string());
                        tx.send(log).unwrap();
                    }
                }
            })
        );
    }

    // Make sure that all threads have completed before continuing execution
    for thread in threads {
        thread.join().unwrap();
    }

    // Report that discovery for this machine is done
    let log = imd::format_log(&ip_address, "Discovery completed");
    tx.send(log)?;

    Ok(())
}

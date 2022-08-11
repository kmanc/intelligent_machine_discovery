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
        threads.push(
            thread::spawn({
                let tx = tx.clone();
                let user = conf.real_user().clone();
                let machine = machine.clone();
                move || {
                    if let Err(e) = discovery(tx.clone(), user, machine) {
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


/*
NOTE - TODO
DOES DISCOVERY NEED THE MACHINE OR JUST THE IP ADDRESS? ASSESS WHEN DONE
NOTE - TODO
*/
fn discovery(tx: mpsc::Sender<String>, user: Arc<imd::IMDUser>, machine: Arc<imd::TargetMachine>) -> Result<(), Box<dyn Error>> {
    // Make sure that the target machine is reachable
    if ping::verify_connection(&tx, &machine.ip_address().to_string()).is_err() {
        return Err(imd::format_log(&machine.ip_address().to_string(), "Target machine could not be reached").into())
    }

    // If the target machine has an associated hostname, add it to the /etc/hosts file
    if let Some(hostname) = machine.hostname() {
        utils::add_to_etc_hosts(&tx, hostname, &machine.ip_address().to_string())?;
    } 

    // Create a landing space for all of the files that results will get written to
    utils::create_dir(&tx, user.clone(), &machine.ip_address().to_string())?;

    // Create a vector for threads. Each will be responsible a sub-task run against the target machine
    let mut threads = vec![];

    // Scan all TCP ports on the machine
    threads.push(
        thread::spawn({
            let tx = tx.clone();
            let user = user.clone();
            let ip_address = machine.ip_address().to_string();
            move || {
                ports::all_tcp_ports(tx, user, &ip_address);
            }
        })
    );

    // Scan NFS server on the machine
    threads.push(
        thread::spawn({
            let tx = tx.clone();
            let user = user.clone();
            let ip_address = machine.ip_address().to_string();
            move || {
                drives::network_drives(tx, user, &ip_address);
            }
        })
    );

    // Scan common TCP ports and perform service discovery
    let port_scan = ports::common_tcp_ports(&tx, user.clone(), &machine.ip_address().to_string())?;

    // Parse the port scan to determine which services are running and where
    let services = utils::parse_port_scan(&tx, &machine.ip_address().to_string(), &port_scan)?;

    let web_location: Arc<String> = match machine.hostname() {
        Some(hostname) => Arc::new(hostname.to_string()),
        None => Arc::new(machine.ip_address().to_string())
    };

    // If an HTTP web server is present, scan for vulnerabilities, directories, and files
    for port in services.get("http").unwrap_or(&vec![]) {
        threads.push(
            thread::spawn({
                let tx = tx.clone();
                let user = user.clone();
                let ip_address = machine.ip_address().to_string();
                let port = port.clone();
                let web_location = web_location.clone();
                move || {
                    web::vuln_scan(tx, user, &ip_address, "http", &port, &web_location);
                }
            })
        );
        threads.push(
            thread::spawn({
                let tx = tx.clone();
                let user = user.clone();
                let ip_address = machine.ip_address().to_string();
                let port = port.clone();
                let web_location = web_location.clone();
                move || {
                    web::directory_scan(tx, user, &ip_address, "http", &port, &web_location);
                }
            })
        );
    }

    // If an HTTPS web server is present, scan for vulnerabilities, directories, and files
    for port in services.get("ssl/http").unwrap_or(&vec![]) {
        println!("HTTPS PORT {port}");
    }

    // Make sure that all threads have completed before continuing execution
    for thread in threads {
        thread.join().unwrap();
    }

    // Report that discovery for this machine is done
    let log = imd::format_log(&machine.ip_address().to_string(), "Discovery completed");
    tx.send(log)?;

    Ok(())
}

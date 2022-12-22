mod conf;
mod drives;
mod ping;
mod ports;
mod utils;
mod web;
use indicatif::MultiProgress;
use std::error::Error;
use std::sync::Arc;
use std::thread;

fn main() {
    // Parse command line arguments and proceed if successful
    let conf = conf::Conf::init();
    post_main(&conf);
}

fn post_main(conf: &conf::Conf) {
    // Create multiprogress bar to house all of the individual bars that update status
    let bars_container = MultiProgress::new();

    // Create a vector for threads. Each will be responsible for one target machine, and will likely spawn its own threads
    let mut threads = vec![];

    // Run the discovery function on each of the target machines in its own thread
    for machine in conf.machines().iter() {
        let discovery_args = imd::DiscoveryArgs::new(
            bars_container.clone(),
            machine.clone(),
            conf.user(),
            conf.wordlist().to_string(),
        );
        let discovery_args = Arc::new(discovery_args);
        threads.push(thread::spawn({
            move || {
                if discovery(&discovery_args).is_err() {}
            }
        }));
    }

    // Make sure that all threads have completed before continuing execution
    for thread in threads {
        thread.join().unwrap();
    }

    println!("Discovery completed for all target machines");
}

fn discovery(args_bundle: &Arc<imd::DiscoveryArgs>) -> Result<(), Box<dyn Error>> {
    // Make sure that the target machine is reachable
    match ping::verify_connection(&args_bundle) {
        Err(_) | Ok(imd::PingResult::Bad) => return Err("Connection".into()),
        Ok(imd::PingResult::Good) => {}
    }

    // If the target machine has a hostname, add it to the /etc/hosts file
    if args_bundle.machine().hostname().is_some() {
        utils::add_to_etc_hosts(&args_bundle).unwrap();
    };

    // Create a landing space for all of the files that results will get written to
    utils::create_dir(&args_bundle)?;

    // Create a vector for threads. Each will be responsible a sub-task run against the target machine
    let mut threads = vec![];

    // Scan all TCP ports on the machine
    threads.push(thread::spawn({
        let args_bundle = args_bundle.clone();
        move || {
            if ports::all_tcp_ports(&args_bundle).is_err() {}
        }
    }));

    // Scan NFS server on the machine
    threads.push(thread::spawn({
        let args_bundle = args_bundle.clone();
        move || {
            if drives::network_drives(&args_bundle).is_err() {}
        }
    }));

    // Scan common TCP ports and perform service discovery
    let port_scan = match ports::common_tcp_ports(&args_bundle.clone()) {
        Ok(port_scan) => port_scan,
        Err(_) => return Err("Common TCP port scan".into()),
    };

    // Parse the port scan to determine which services are running and where
    let services = utils::parse_port_scan(&args_bundle.clone(), &port_scan);
    let services = Arc::new(services);

    // For now we are only parsing web servers, so scan them for vulnerabilities, directories, and files
    for (service, ports) in services.iter() {
        for port in ports {
            // Spin up a thread for the vuln scan
            threads.push(thread::spawn({
                let args_bundle = args_bundle.clone();
                let port = port.clone();
                let service = service.clone();
                move || {
                    if web::vuln_scan(&args_bundle, &service, &port).is_err() {}
                }
            }));
            // Spin up a thread for the web dir and file scanning
            threads.push(thread::spawn({
                let args_bundle = args_bundle.clone();
                let port = port.clone();
                let service = service.clone();
                move || {
                    if web::dir_and_file_scan(&args_bundle, &service, &port).is_err() {}
                }
            }));
        }
    }

    // Make sure that all threads have completed before continuing execution
    for thread in threads {
        thread.join().unwrap();
    }

    Ok(())
}

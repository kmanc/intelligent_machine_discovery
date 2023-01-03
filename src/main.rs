mod conf;
use conf::Conf;
/*mod drives;
mod ping;
mod ports;
mod utils;
mod web;*/
use std::thread;

fn main() {
    // Parse command line arguments and proceed if successful
    if let Some(conf) = Conf::init(){
        post_main(&conf);
    }
}

fn post_main(conf: &Conf) {
    // Create a vector for threads. Each will be responsible for one target machine, and will likely spawn its own threads
    let mut threads: Vec<_> = vec![];

    for machine in conf.machines().iter() {
        let machine_clone = machine.clone();
        threads.push(thread::spawn(move || machine_clone.discovery()));
    }

    for thread in threads {
        thread.join().unwrap();
    }

    /*
    // Run the discovery function on each of the target machines in its own thread
    for machine in conf.machines().iter() {
        let discovery_args = imd::DiscoveryArgs::new(
            bars_container.clone(),
            machine.clone(),
            conf.user(),
            conf.wordlist().to_string(),
        );
        let discovery_args = Arc::new(discovery_args);
        threads.push(thread::spawn(move || discovery(&discovery_args)));
    }

    // Make sure that all threads have completed before continuing execution
    for thread in threads {
        thread.join().unwrap();
    }
    */

    println!("Discovery completed for all target machines");
}

/*
fn discovery(args_bundle: &Arc<imd::DiscoveryArgs>) {
    // Make sure that the target machine is reachable
    match ping::verify_connection(&args_bundle.clone()) {
        imd::IMDOutcome::Bad => return,
        imd::IMDOutcome::Good | imd::IMDOutcome::Neutral => {}
    }

    /*

    // If the target machine has a hostname, add it to the /etc/hosts file
    if args_bundle.machine().hostname().is_some() {
        utils::add_to_etc_hosts(&args_bundle.clone());
    };

    // Create a landing space for all of the files that results will get written to
    utils::create_dir(&args_bundle.clone());

    // Create a vector for threads. Each will be responsible a sub-task run against the target machine
    let mut threads = vec![];

    // Scan all TCP ports on the machine
    threads.push(thread::spawn({
        let args_bundle = args_bundle.clone();
        move || ports::all_tcp_ports(&args_bundle)
    }));

    // Scan NFS server on the machine
    threads.push(thread::spawn({
        let args_bundle = args_bundle.clone();
        move || drives::network_drives(&args_bundle)
    }));

    // Scan common TCP ports and perform service discovery
    let port_scan = ports::common_tcp_ports(&args_bundle.clone());

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
                    web::vuln_scan(&args_bundle, &service, &port);
                }
            }));
            // Spin up a thread for the web dir and file scanning
            threads.push(thread::spawn({
                let args_bundle = args_bundle.clone();
                let port = port.clone();
                let service = service.clone();
                move || {
                    web::dir_and_file_scan(&args_bundle, &service, &port);
                }
            }));
        }
    }

    // Make sure that all threads have completed before continuing execution
    for thread in threads {
        thread.join().unwrap();
    }

    */
}
*/

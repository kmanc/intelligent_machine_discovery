mod args;
mod ping;
mod utils;
use std::error::Error;
use std::sync::{Arc, mpsc};
use std::thread;


fn main() {
    // Parse command line arguments and proceed if successful
    match args::Args::parse(){
        Ok(args) => post_main(args),
        Err(e) => eprintln!("{e}"),
    }
}


fn post_main(args: args::Args) {
    // Create send / receive channels
    let (tx, rx) = mpsc::channel();

    // Create a vector for threads. Each will be responsible for one target machine, and will likely spawn its own threads
    let mut threads = vec![];

    // Run the discovery function on each of the target machines in its own thread
    for machine in args.machines().iter() {
        threads.push(
            thread::spawn({
                let tx = tx.clone();
                let user = args.real_user().clone();
                let machine = machine.clone();
                move || {
                    if let Err(e) = discovery(tx.clone(), user, machine) {
                        tx.send(e.to_string()).unwrap();
                    }
                }
            })        
        )
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


fn discovery(tx: mpsc::Sender<String>, user: Arc<imd::IMDUser>, machine: Arc<imd::TargetMachine>) -> Result<(), Box<dyn Error>> {
    // Make sure that the target machine is reachable
    /*
    if ping::verify_connection(tx.clone(), &machine.ip_address().to_string()).is_err() {
        return Err(imd::format_log(&machine.ip_address().to_string(), "Target machine could not be reached").into())
    }
    */

    // If the target machine has an associated hostname, add it to the /etc/hosts file
    /*
    if let Some(hostname) = machine.hostname() {
        utils::add_to_etc_hosts(tx.clone(), hostname, &machine.ip_address().to_string())?;
    }
    */    

    // Create a landing space for all of the files that results will get written to
    utils::create_dir(tx.clone(), user.clone(), &machine.ip_address().to_string())?;
    Ok(())
}

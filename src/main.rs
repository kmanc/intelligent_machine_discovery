mod args;
use std::error::Error;
use std::fs;
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

fn create_dir(tx: mpsc::Sender<String>, user: Arc<imd::IMDUser>, ip_address: &str) -> Result<(), Box<dyn Error>> {
    // Report that we are creating the directory
    let log = imd::format_log(ip_address, "Creating directory to store results in");
    tx.send(log)?;

    // If it fails, it's probably because the directory already exists (not 100%, but pretty likely), so report that and move on
    if let Err(_) = fs::create_dir(ip_address) {
        let log = imd::format_log(ip_address, "Directory already exists, skipping");
        tx.send(log)?;
    }

    // Change ownership of the directory to the logged in user from Args
    imd::change_owner(ip_address, user)?;

    Ok(())
}

fn discovery(tx: mpsc::Sender<String>, user: Arc<imd::IMDUser>, machine: Arc<imd::TargetMachine>) -> Result<(), Box<dyn Error>> {
    // Create a landing space for all of the files that results will get written to
    create_dir(tx.clone(), user.clone(), &machine.ip_address().to_string())?;
    Ok(())
}
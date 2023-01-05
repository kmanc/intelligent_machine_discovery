mod conf;
use conf::Conf;
use std::thread;

fn main() {
    // Parse command line arguments and proceed if successful
    if let Some(conf) = Conf::init() {
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

    println!("Discovery completed for all target machines");
}

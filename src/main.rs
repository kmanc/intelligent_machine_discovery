mod conf;
use conf::Conf;
use std::thread;

fn main() {
    // Parse command line arguments and proceed if successful
    let conf = Conf::init();

    // Create a vector for threads. Each will be responsible for one target machine, and will likely spawn its own threads
    let mut threads: Vec<std::thread::JoinHandle<()>> = vec![];

    for machine in conf.target_machines().iter() {
        let machine = machine.clone();
        let user = conf.user();
        let wordlist = conf.wordlist();
        threads.push(thread::spawn(move || machine.discovery(user, wordlist)));
    }

    for thread in threads {
        thread.join().unwrap();
    }

    println!("Discovery for all target machines is complete");
}

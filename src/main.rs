//use imd::Config;
mod args;
//use std::io::Write;
use std::sync::mpsc;
//use std::thread;
//use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

fn main() {
    match args::Args::parse(){
        Ok(args) => post_main(args),
        Err(e) => println!("{e}"),
    }
}

fn post_main(args: args::Args) {
    // Create send / receive channels
    let (tx, rx) = mpsc::channel();

    println!("{args:?}");

    tx.send("a".to_string()).unwrap();

    // Drop the main function's transmitter or execution will never stop
    drop(tx);

    // Handle the receive channel messages
    for received in rx {
        println!("{received}");
    }

    println!("Done");
}
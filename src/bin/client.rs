extern crate clap;
use clap::{App, Arg, ArgMatches};
use std::io::Write;
use std::net::IpAddr;

fn main() {
    let port = rip::DEFAULT_PORT.to_string();
    let args = App::new(rip::NAME)
        .version(rip::VERSION)
        .author(rip::AUTHOR)
        .about(rip::ABOUT)
        .arg(
            Arg::with_name("port")
                .short("p")
                .long("port")
                .help("Set a different port from the default of 44353")
                .default_value(&port)
                .takes_value(true),
        ).arg(
            Arg::with_name("host")
                .help("Sets the Rip server host")
                .required(true)
                .index(1),
        ).get_matches();

    match run(&args) {
        Ok(ip) => {
            print!("{}", ip);
            std::io::stdout().flush().unwrap();
        }
        Err(err) => {
            println!("{}", err);
            std::process::exit(1);
        }
    }
}

fn run(args: &ArgMatches) -> Result<IpAddr, String> {
    let port_str = args.value_of("port").unwrap();
    let port: u16 = match port_str.parse() {
        Ok(v) => v,
        Err(_) => return Err("Port must be a valid unsigned 16bit integer".to_string()),
    };

    let dest = match rip::parse_socket_addr(args.value_of("host").unwrap(), port) {
        Ok(v) => v,
        Err(err) => return Err(err),
    };

    rip::run_client(dest)
}

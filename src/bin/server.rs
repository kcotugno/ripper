extern crate clap;
use clap::{App, Arg, ArgMatches};

const NAME: &str = "rip-server";

fn main() {
    let port = rip::DEFAULT_PORT.to_string();
    let args = App::new(NAME)
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
        ).get_matches();

    let result = run(&args);
    if result.is_err() {
        println!("{}", result.err().unwrap());
        std::process::exit(1);
    }
}

fn run(args: &ArgMatches) -> Result<(), String> {
    let port_str = args.value_of("port").unwrap();
    let port: u16 = match port_str.parse() {
        Ok(v) => v,
        Err(_) => return Err("Port must be a valid unsigned 16bit integer".to_string()),
    };

    rip::run_server(port)
}

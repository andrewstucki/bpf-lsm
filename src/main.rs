use std::env;
use std::convert::TryFrom;
use seahorse::{App, Context, Flag, FlagType};
use probe_sys::{Event, Probe};

fn main() {
    let args: Vec<String> = env::args().collect();
    let app = App::new(env!("CARGO_PKG_NAME"))
        .description(env!("CARGO_PKG_DESCRIPTION"))
        .version(env!("CARGO_PKG_VERSION"))
        .action(run)
        .flag(
            Flag::new("filter", FlagType::Int)
                .description("Deny execs from the given uid")
                .alias("f"),
        );
        
    app.run(args)
}

fn run(c: &Context) {
    let filtered_uid = match c.int_flag("filter") {
        Ok(id) => match u32::try_from(id).ok() {
            Some(uid) => uid,
            _ => std::u32::MAX,
        },
        _ => std::u32::MAX,
    };

    match Probe::filter(filtered_uid).run(|e: Event| {
        println!("{:?}", e);
    }) {
        Ok(probe) => {
            loop {
                probe.poll(10000);
            }
        }
        Err(error) => {
            println!("{}", error);
        }
    }
}

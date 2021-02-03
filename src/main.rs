use log::{debug, error};
use probe_sys::{Probe, Transformer};
use seahorse::{App, Context, Flag, FlagType};
use sled::Config;
use std::convert::TryFrom;

mod errors;
mod globals;
mod handler;
mod logging;

use crate::globals::{global_database, initialize_global_database};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let app = App::new(env!("CARGO_PKG_NAME"))
        .description(env!("CARGO_PKG_DESCRIPTION"))
        .version(env!("CARGO_PKG_VERSION"))
        .action(run)
        .flag(
            Flag::new("filter", FlagType::Int)
                .description("Deny execs from the given uid")
                .alias("f"),
        )
        .flag(
            Flag::new("debug", FlagType::Bool)
                .description("Verbose debugging")
                .alias("d"),
        )
        .flag(
            Flag::new("workers", FlagType::Int)
                .description("Number of workers (default: #cores)")
                .alias("w"),
        );

    app.run(args)
}

fn run(c: &Context) {
    let config = Config::new().temporary(true);
    let db = config.open().expect("could not open database");
    initialize_global_database(db);

    let debug = c.bool_flag("debug");
    logging::setup_logger(if debug {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    });

    let filtered_uid = c.int_flag("filter").map_or(std::u32::MAX, |id| {
        u32::try_from(id).unwrap_or(std::u32::MAX)
    });

    let cores = num_cpus::get() as u32;
    let workers = c
        .int_flag("workers")
        .map_or(cores, |w| u32::try_from(w).unwrap_or(cores));

    let (mut tx, rx) = spmc::channel();
    for i in 0..workers {
        let transformer = Transformer::new(handler::Handler {});
        let rx = rx.clone();
        std::thread::spawn(move || loop {
            match rx.recv() {
                Ok((key, data)) => {
                    match transformer.transform(data) {
                        Ok(json) => println!("{}", json),
                        Err(e) => error!("worker {}: {:?}", i, e),
                    };
                    // batch the transformations up and then remove in a transaction
                    match global_database().remove(key) {
                        Ok(_) => debug!("worker {}: cleaned record", i),
                        Err(e) => error!("worker {}: error removing record {:?}", i, e),
                    }
                }
                Err(e) => error!("worker {}: {}", i, e.to_string()),
            }
        });
    }

    std::thread::spawn(move || {
        let mut subscriber = global_database().watch_prefix(vec![]);
        loop {
            match subscriber.next() {
                Some(event) => {
                    for (_, key, data) in event.into_iter() {
                        if data.is_some() {
                            let value = data.clone().unwrap().to_vec();
                            let result = tx.send((key.clone(), value));
                            if result.is_err() {
                                error!("sender: {}", result.unwrap_err().to_string());
                            }
                        }
                    }
                }
                None => {
                    debug!("subscriber closed");
                    break;
                }
            }
        }
    });

    match Probe::new()
        .debug(debug)
        .filter(filtered_uid)
        .run(handler::Handler {})
    {
        Ok(probe) => loop {
            probe.poll(-1);
        },
        Err(e) => {
            error!("error setting up probe: {}", e.to_string());
            std::process::exit(1);
        }
    }
}

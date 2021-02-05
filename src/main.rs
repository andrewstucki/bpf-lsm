use log::error;
use seahorse::{App, Context, Flag, FlagType};
use std::convert::{TryFrom, TryInto};

mod batcher;
mod client;
mod errors;
mod globals;
mod handler;
mod logging;

#[cfg(test)]
mod tests;

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
        )
        .flag(
            Flag::new("flush", FlagType::Int)
                .description("Maximum seconds before a flush occurs (default: 30s)")
                .alias("r"),
        )
        .flag(
            Flag::new("batch", FlagType::Int)
                .description("Maximum batch size before a flush occurs (default: 1000)")
                .alias("b"),
        )
        .flag(
            Flag::new("size", FlagType::Int)
                .description("Maximum batch size (in bytes) before a flush occurs (default: 1MB)")
                .alias("s"),
        );

    app.run(args)
}

fn run(c: &Context) {
    let config = sled::Config::new().temporary(true);
    let db = config.open().expect("could not open database");
    globals::initialize_global_database(db);

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

    let batch_size = c
        .int_flag("batch")
        .map_or(500, |w| usize::try_from(w).unwrap_or(500));

    let batch_bytes = c
        .int_flag("size")
        .map_or(1 << 20, |w| usize::try_from(w).unwrap_or(1 << 20));

    let flush_rate = c
        .int_flag("flush")
        .map_or(30, |w| u64::try_from(w).unwrap_or(30));

    std::thread::spawn(move || loop {
        batcher::Batcher::run(flush_rate, batch_size, batch_bytes, workers)
    });

    match probe_sys::Probe::new()
        .debug(debug)
        .filter(filtered_uid)
        .run(handler::Handler {})
    {
        Ok(probe) => loop {
            probe.poll((flush_rate * 1000).try_into().unwrap());
        },
        Err(e) => {
            error!("error setting up probe: {}", e.to_string());
            std::process::exit(1);
        }
    }
}

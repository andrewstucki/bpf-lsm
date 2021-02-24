use log::error;
use seahorse::{App, Context, Flag, FlagType};
use std::convert::{TryFrom, TryInto};
use std::time::Duration;

use crate::client::Client;

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
            Flag::new("filter", FlagType::String)
                .description("Apply filter to the probe")
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
        )
        .flag(
            Flag::new("host", FlagType::String)
                .description(
                    "Elasticsearch host that data is sent to (default: 'http://localhost:9200')",
                )
                .alias("h"),
        )
        .flag(
            Flag::new("creds", FlagType::String)
                .description("Credentials for Elasticsearch host")
                .alias("c"),
        )
        .flag(
            Flag::new("insecure", FlagType::Bool)
                .description("Allow for insecure https connections to Elasticsearch host")
                .alias("i"),
        )
        .flag(
            Flag::new("timeout", FlagType::Int)
                .description("Request timeout for Elasticsearch client (default: 5s)")
                .alias("t"),
        )
        .flag(
            Flag::new("local", FlagType::Bool)
                .description(
                    "Don't attempt to flush any output to Elasticsearch, just echo it to stdout",
                )
                .alias("l"),
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

    let mut filters: Vec<&str> = vec![];
    let filter = c.string_flag("filter").unwrap_or_else(|_| String::from(""));
    if !filter.is_empty() {
        filters = filter.split(';').collect();
    }

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

    let host = c
        .string_flag("host")
        .unwrap_or_else(|_| String::from("http://localhost:9200"));
    let creds = c.string_flag("creds").ok();
    let insecure = c.bool_flag("insecure");
    let timeout = c
        .int_flag("timeout")
        .map_or(5, |t| u64::try_from(t).unwrap_or(5));
    let local = c.bool_flag("local");

    let client = Client::new(host, creds, insecure, Duration::new(timeout, 0));
    match setup_templates(local, &client) {
        Err(e) => {
            error!("error setting up templates: {}", e);
            std::process::exit(1);
        }
        _ => {}
    }
    std::thread::spawn(move || loop {
        batcher::Batcher::run(local, &client, flush_rate, batch_size, batch_bytes, workers)
    });

    match probe_sys::Probe::new()
        .debug(debug)
        .run(handler::Handler {})
    {
        Ok(probe) => match probe.apply(filters) {
            Err(e) => {
                error!("error setting up probe: {}", e);
                std::process::exit(1);
            }
            _ => loop {
                probe.poll((flush_rate * 1000).try_into().unwrap());
            },
        },
        Err(e) => {
            error!("error setting up probe: {}", e.to_string());
            std::process::exit(1);
        }
    }
}

fn setup_templates(local: bool, client: &Client) -> Result<(), String> {
    if !local {
        client.ensure_template("bprm_check_security")?;
        client.ensure_template("inode_unlink")?;
    }
    Ok(())
}

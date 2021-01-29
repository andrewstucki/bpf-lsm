#[macro_use]
extern crate may;

#[macro_use]
extern crate lazy_static;

use log::{debug, error, warn, LevelFilter};
use probe_sys::{BprmCheckSecurityEvent, Probe, ProbeHandler, SerializableEvent};
use seahorse::{App, Context, Flag, FlagType};
use sled::{Config, Db};
use std::convert::TryFrom;
use std::env;
use std::error;
use std::fmt;

lazy_static! {
    static ref DB: Db = {
        let config = Config::new().temporary(true);
        config.open().unwrap()
    };
}

#[derive(Debug)]
pub enum Error {
    EnqueuingError(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::EnqueuingError(ref e) => write!(f, "could not enqueue data: {}", e),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Error::EnqueuingError(..) => None,
        }
    }
}

fn setup_logger(level: LevelFilter) {
    let result = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}] {}",
                chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                record.target(),
                record.level(),
                message
            ))
        })
        .level(level)
        .chain(std::io::stderr())
        .apply();
    if result.is_err() {
        eprintln!(
            "Error initializing logging: {:}",
            result.unwrap_err().to_string()
        );
        std::process::exit(1);
    }
}

#[derive(Clone)]
struct Handler {}

impl Handler {
    fn enqueue<T>(&self, event: &mut T) -> Result<(), Error>
    where
        T: SerializableEvent + std::fmt::Debug,
    {
        let data = event
            .to_bytes()
            .map_err(|e| Error::EnqueuingError(e.to_string()))?;
        DB.insert(b"1", data)
            .map_err(|e| Error::EnqueuingError(e.to_string()))?;
        Ok(())
    }
}

impl ProbeHandler for Handler {
    fn handle_bprm_check_security(&self, event: &mut BprmCheckSecurityEvent) {
        debug!("enqueueing");
        self.enqueue(event)
            .unwrap_or_else(|e| warn!("error sending data: {}", e));
    }
}

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
        )
        .flag(
            Flag::new("debug", FlagType::Bool)
                .description("Verbose debugging")
                .alias("d"),
        );

    app.run(args)
}

fn run(c: &Context) {
    setup_logger(if c.bool_flag("debug") {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    });

    let filtered_uid = c.int_flag("filter").map_or(std::u32::MAX, |id| {
        u32::try_from(id).unwrap_or(std::u32::MAX)
    });

    let subscriber = DB.watch_prefix(vec![]);
    go!(move || {
        for _event in subscriber.take(1) {
            debug!("data");
        }
        debug!("finished consuming channel");
    });

    match Probe::new().filter(filtered_uid).run(Handler {}) {
        Ok(probe) => loop {
            probe.poll(10000);
        },
        Err(e) => {
            error!("error setting up probe: {}", e.to_string());
            std::process::exit(1);
        }
    }
}

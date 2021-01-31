use log::{debug, error, LevelFilter};
use num_cpus;
use once_cell::sync::OnceCell;
use probe_sys::{
    BprmCheckSecurityEvent, Probe, ProbeHandler, SerializableEvent, SerializableResult,
    TransformationHandler, Transformer,
};
use seahorse::{App, Context, Flag, FlagType};
use sled::{Config, Db};
use spmc;
use std::convert::TryFrom;
use std::env;
use std::error;
use std::fmt;
use uuid::Uuid;

static DB_INSTANCE: OnceCell<Db> = OnceCell::new();

pub fn global_database() -> &'static Db {
    DB_INSTANCE.get().expect("database is not initialized")
}

pub fn initialize_global_database(db: Db) {
    DB_INSTANCE
        .set(db)
        .expect("database could not be initialized");
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

struct Handler {}

impl ProbeHandler<Error> for Handler {
    fn enqueue<T>(&self, event: &mut T) -> Result<(), Error>
    where
        T: SerializableEvent + std::fmt::Debug,
    {
        let db = global_database();
        let uuid = Uuid::new_v4();
        let sequence = db
            .generate_id()
            .map_err(|e| Error::EnqueuingError(e.to_string()))?;

        let mut buffer = Uuid::encode_buffer();
        let event_id = uuid.to_hyphenated().encode_lower(&mut buffer);
        event.update_id(event_id);
        event.update_sequence(sequence);

        let data = event
            .to_bytes()
            .map_err(|e| Error::EnqueuingError(e.to_string()))?;
        db.insert(
            [&sequence.to_be_bytes()[..], uuid.as_bytes()].concat(),
            data,
        )
        .map_err(|e| Error::EnqueuingError(e.to_string()))?;
        Ok(())
    }
}

impl TransformationHandler for Handler {
    fn enrich_bprm_check_security<'a>(
        &self,
        event: &'a mut BprmCheckSecurityEvent,
    ) -> SerializableResult<&'a mut BprmCheckSecurityEvent> {
        event.enrich_common()?;
        Ok(event)
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

    setup_logger(if c.bool_flag("debug") {
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

    std::thread::spawn(
        move || match Probe::new().filter(filtered_uid).run(Handler {}) {
            Ok(probe) => loop {
                probe.poll(-1);
            },
            Err(e) => {
                error!("error setting up probe: {}", e.to_string());
                std::process::exit(1);
            }
        },
    );

    let (mut tx, rx) = spmc::channel();
    for i in 0..workers {
        let transformer = Transformer::new(Handler {});
        let rx = rx.clone();
        std::thread::spawn(move || loop {
            match rx.recv() {
                Ok((key, data)) => {
                    match transformer.transform(data) {
                        Ok(json) => debug!("worker {}: {:?}", i, json),
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
}

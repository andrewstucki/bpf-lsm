use log::{debug, error};

use crate::globals::global_database;

pub struct Batcher {}

impl Batcher {
    pub fn run(workers: u32) {
        let (mut tx, rx) = spmc::channel();
        for i in 0..workers {
            let transformer = probe_sys::Transformer::new(crate::handler::Handler {});
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
}

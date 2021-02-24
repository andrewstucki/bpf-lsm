use log::{debug, error};
use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, SystemTime};

use crate::client::Client;
use crate::globals::global_database;

pub struct Batcher {}

impl Batcher {
    pub fn run(
        local: bool,
        client: &Client,
        flush_rate: u64,
        max_batch_size: usize,
        max_batch_bytes: usize,
        workers: u32,
    ) {
        let (mut tx, rx) = spmc::channel();
        for i in 0..workers {
            let worker_client = client.clone();
            let transformer = probe_sys::Transformer::new(crate::handler::Handler {});
            let rx = rx.clone();
            let flush_timeout = Duration::new(flush_rate, 0);
            std::thread::spawn(move || {
                let mut batch = Vec::new();
                let mut current_batch_bytes: usize = 0;
                let mut last_flush = SystemTime::now();
                loop {
                    match rx.recv_timeout(flush_timeout) {
                        Ok((key, data)) => {
                            match transformer.transform(data) {
                                Ok((index, json)) => {
                                    current_batch_bytes += json.chars().count() + 1; // 1 == newline
                                    batch.push((key, (index, json)));
                                }
                                Err(e) => error!("worker {}: {:?}", i, e),
                            };
                        }
                        Err(RecvTimeoutError::Disconnected) => {
                            error!("worker disconnected");
                            break;
                        }
                        Err(RecvTimeoutError::Timeout) => {}
                    }
                    let now = SystemTime::now();
                    let batch_size = batch.len();
                    // flush immediately if we have a clock reset
                    let elapsed = now
                        .duration_since(last_flush)
                        .unwrap_or(flush_timeout)
                        .as_secs();
                    if current_batch_bytes >= max_batch_bytes
                        || batch_size >= max_batch_size
                        || elapsed > flush_rate
                    {
                        if !local {
                            match worker_client.send_batch(&batch) {
                                Err(e) => error!("error sending batch: {}", e),
                                _ => {}
                            }
                        }
                        for (k, (_, v)) in &batch {
                            if local {
                                println!("{}", v);
                            }
                            match global_database().remove(k) {
                                Ok(_) => debug!("worker {}: cleaned record", i),
                                Err(e) => error!("worker {}: error removing record {:?}", i, e),
                            }
                        }
                        batch.clear();
                        current_batch_bytes = 0;
                        last_flush = now;
                    }
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

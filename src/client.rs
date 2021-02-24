#![allow(dead_code)]

use crate::globals::get_template;
use backoff::backoff::Backoff;
use backoff::{retry, ExponentialBackoff, SystemClock};
use base64::encode;
use instant::Instant;
use std::format;
use std::sync::Arc;
use std::time::Duration;
use ureq::{Agent, AgentBuilder, Error};
use sled::IVec;

pub struct SkipVerifier {}

impl rustls::ServerCertVerifier for SkipVerifier {
    fn verify_server_cert(
        &self,
        _roots: &rustls::RootCertStore,
        _presented_certs: &[rustls::Certificate],
        _dns_name: webpki::DNSNameRef<'_>,
        _ocsp_response: &[u8],
    ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        Ok(rustls::ServerCertVerified::assertion())
    }
}

const INITIAL_INTERVAL_MILLIS: u64 = 500;
const RANDOMIZATION_FACTOR: f64 = 0.5;
const MULTIPLIER: f64 = 1.5;
const MAX_INTERVAL_MILLIS: u64 = 2_000;
const MAX_ELAPSED_TIME_MILLIS: u64 = 15_000;

#[derive(Clone)]
pub struct Client {
    inner: Agent,
    base: String,
    creds: Option<String>,
}

fn make_url(base: String, path: String) -> String {
    base.trim_end_matches('/').to_owned() + &path
}

fn backoff() -> ExponentialBackoff {
    let mut e = ExponentialBackoff {
        current_interval: Duration::from_millis(INITIAL_INTERVAL_MILLIS),
        initial_interval: Duration::from_millis(INITIAL_INTERVAL_MILLIS),
        randomization_factor: RANDOMIZATION_FACTOR,
        multiplier: MULTIPLIER,
        max_interval: Duration::from_millis(MAX_INTERVAL_MILLIS),
        max_elapsed_time: Some(Duration::from_millis(MAX_ELAPSED_TIME_MILLIS)),
        clock: SystemClock::default(),
        start_time: Instant::now(),
    };
    e.reset();
    e
}

impl Client {
    pub fn new(
        base: String,
        creds: Option<String>,
        ignore_validation: bool,
        timeout: std::time::Duration,
    ) -> Self {
        let mut agent_builder = AgentBuilder::new().timeout(timeout);
        if ignore_validation {
            let mut client_config = rustls::ClientConfig::new();
            client_config
                .dangerous()
                .set_certificate_verifier(Arc::new(SkipVerifier {}));
            let tls_config = Arc::new(client_config);
            agent_builder = agent_builder.tls_config(tls_config)
        }
        let encoded = creds.map(|c| encode(c.as_bytes()));
        Self {
            base,
            creds: encoded,
            inner: agent_builder.build(),
        }
    }

    fn construct_request(&self, method: &str, content_type: &str, url: &String) -> ureq::Request {
        let path = format!("{}{}", self.base, url);
        let request = self
            .inner
            .request(method, &path)
            .set("Content-Type", content_type);
        match &self.creds {
            Some(creds) => {
                let header = format!("Basic {}", creds);
                request.set("Authorization", &header)
            }
            None => request,
        }
    }

    fn construct_basic_request(&self, method: &str, url: &String) -> ureq::Request {
        self.construct_request(method, "application/json", url)
    }

    fn construct_bulk_request(&self, method: &str, url: &String) -> ureq::Request {
        self.construct_request(method, "application/x-ndjson", url)
    }

    fn do_request(
        &self,
        method: &str,
        url: &String,
        data: Option<&[u8]>,
    ) -> Result<String, String> {
        let response = match data {
            Some(payload) => retry(backoff(), || {
                let resp = self
                    .construct_basic_request(method, url)
                    .send_bytes(payload);
                match resp {
                    Ok(r) => Ok(r),
                    Err(Error::Status(_, r)) => Ok(r),
                    Err(e) => Err(backoff::Error::Transient(e)),
                }
            }),
            None => retry(backoff(), || {
                let resp = self.construct_basic_request(method, url).call();
                match resp {
                    Ok(r) => Ok(r),
                    Err(Error::Status(_, r)) => Ok(r),
                    Err(e) => Err(backoff::Error::Transient(e)),
                }
            }),
        };
        let response_text = response
            .map_err(|e| e.to_string())?
            .into_string()
            .map_err(|e| e.to_string())?;
        let error_message = ajson::get(&response_text, "error.reason");
        match error_message {
            Some(message) => Err(message.to_string()),
            None => Ok(response_text),
        }
    }

    fn get(&self, url: &String) -> Result<String, String> {
        self.do_request("GET", url, None)
    }

    fn put(&self, url: &String, data: &[u8]) -> Result<String, String> {
        self.do_request("PUT", url, Some(data))
    }

    pub fn ensure_template(&self, name: &str) -> Result<(), String> {
        let url = format!("/_index_template/{}", name);
        match self.get(&url) {
            Ok(_) => Ok(()), // we already have the template, don't bother creating a new one
            Err(_) => {
                // assume we don't have the template installed, so attempt to install it
                let template = get_template(name)?;
                self.put(&url, template)?;
                Ok(())
            }
        }
    }

    pub fn send_batch(&self, _batch: &Vec<(IVec, String)>) -> Result<(), String> {
        Ok(())
    }
}

// don't ever mutate state in the client
unsafe impl Send for Client {}
unsafe impl Sync for Client {}

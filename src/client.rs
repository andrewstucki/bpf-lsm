use std::sync::Arc;
use ureq::{Agent, AgentBuilder};
use instant::Instant;
use std::time::Duration;
use backoff::{SystemClock, ExponentialBackoff};
use backoff::backoff::Backoff;

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
    creds: String,
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
        url: String,
        creds: String,
        ignore_validatation: bool,
        timeout: std::time::Duration,
    ) -> Self {
        let mut agent_builder = AgentBuilder::new().timeout(timeout);
        if ignore_validatation {
            let mut client_config = rustls::ClientConfig::new();
            client_config
                .dangerous()
                .set_certificate_verifier(Arc::new(SkipVerifier {}));
            let tls_config = Arc::new(client_config);
            agent_builder = agent_builder.tls_config(tls_config)
        }
        Self {
            base: url,
            creds: creds,
            inner: agent_builder.build(),
        }
    }
}

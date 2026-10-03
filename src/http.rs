//! HTTP transport used to talk to Vault.
//!
//! A PostgreSQL backend is single-threaded and must keep reacting to query
//! cancellation, `statement_timeout` and termination while it waits on the
//! network. Each request therefore runs on a short-lived worker thread (with
//! every signal blocked, so PostgreSQL's handlers keep running on the backend
//! thread) while the backend polls for the result and services interrupts.
//! The worker never calls into PostgreSQL.
//!
//! The backend waits at most `pii_vault.timeout_ms` for a request. A worker
//! that is left behind (query cancelled, or deadline passed) ends on its own:
//! every phase of the request (connect, send, receive) has the same timeout,
//! and name resolution runs on the worker itself. At most
//! `MAX_LIVE_WORKERS` workers may be alive per backend; beyond that, new
//! requests fail at once instead of piling up threads and sockets.

use crate::config::{self, TransportSettings};
use crate::error::PiiError;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use ureq::tls::{Certificate, ClientCert, PemItem, PrivateKey, RootCerts, TlsConfig, TlsProvider};
use zeroize::Zeroizing;

const MAX_RESPONSE_BYTES: u64 = 1 << 20;
const INTERRUPT_POLL: Duration = Duration::from_millis(20);
/// Workers of this backend that may be alive at the same time.
const MAX_LIVE_WORKERS: usize = 4;

static LIVE_WORKERS: AtomicUsize = AtomicUsize::new(0);

/// Decrements `LIVE_WORKERS` when the worker thread ends.
struct WorkerSlot;

impl Drop for WorkerSlot {
    fn drop(&mut self) {
        LIVE_WORKERS.fetch_sub(1, Ordering::AcqRel);
    }
}

/// How long an idle connection to Vault is kept for reuse. Long enough to
/// spare occasional requests a new TLS handshake, shorter than the idle
/// timeouts of Vault (5 minutes) and of common load balancers (60 seconds).
const KEEP_ALIVE: Duration = Duration::from_secs(50);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Delete,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Delete => "DELETE",
        }
    }
}

pub struct Request {
    pub method: Method,
    pub url: String,
    pub token: Option<Zeroizing<String>>,
    pub namespace: Option<String>,
    /// May carry plaintext (Transit encryption), hence wiped on drop.
    pub json_body: Option<Zeroizing<Vec<u8>>>,
}

pub struct Response {
    pub status: u16,
    pub body: Zeroizing<Vec<u8>>,
}

#[derive(Debug)]
pub enum TransportError {
    /// The request did not complete within `pii_vault.timeout_ms`.
    Timeout,
    /// The connection could not be established or broke; worth retrying.
    Connect(String),
    /// Anything else (TLS failure, malformed response, ...); not retried.
    Other(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Timeout => write!(f, "request timed out"),
            TransportError::Connect(m) | TransportError::Other(m) => write!(f, "{m}"),
        }
    }
}

struct AgentSlot {
    settings: TransportSettings,
    file_stamps: Vec<Option<SystemTime>>,
    agent: ureq::Agent,
}

// One client per backend so keep-alive connections are reused; rebuilt when
// the TLS/timeout settings or the certificate files change.
static AGENT: Mutex<Option<AgentSlot>> = Mutex::new(None);

fn file_stamps(s: &TransportSettings) -> Vec<Option<SystemTime>> {
    [&s.ca_file, &s.client_cert_file, &s.client_key_file]
        .into_iter()
        .map(|p| {
            p.as_ref()
                .and_then(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok())
        })
        .collect()
}

fn agent() -> Result<ureq::Agent, PiiError> {
    let settings = config::transport();
    let stamps = file_stamps(&settings);
    let mut slot = AGENT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(s) = slot.as_ref() {
        if s.settings == settings && s.file_stamps == stamps {
            return Ok(s.agent.clone());
        }
    }
    let agent = build_agent(&settings)?;
    *slot = Some(AgentSlot {
        settings,
        file_stamps: stamps,
        agent: agent.clone(),
    });
    Ok(agent)
}

fn read_pem(path: &str, what: &str) -> Result<Zeroizing<Vec<u8>>, PiiError> {
    std::fs::read(path)
        .map(Zeroizing::new)
        .map_err(|e| PiiError::Config(format!("cannot read {what} \"{path}\": {e}")))
}

fn certificates(pem: &[u8], path: &str, what: &str) -> Result<Vec<Certificate<'static>>, PiiError> {
    let certs: Vec<Certificate<'static>> = ureq::tls::parse_pem(pem)
        .filter_map(|item| match item {
            Ok(PemItem::Certificate(c)) => Some(c),
            _ => None,
        })
        .collect();
    if certs.is_empty() {
        return Err(PiiError::Config(format!(
            "{what} \"{path}\" contains no PEM certificate"
        )));
    }
    Ok(certs)
}

fn build_agent(s: &TransportSettings) -> Result<ureq::Agent, PiiError> {
    let mut tls = TlsConfig::builder().provider(TlsProvider::Rustls);
    tls = match &s.ca_file {
        Some(path) => {
            let pem = read_pem(path, "pii_vault.ca_file")?;
            let roots = certificates(&pem, path, "pii_vault.ca_file")?;
            tls.root_certs(RootCerts::Specific(Arc::new(roots)))
        }
        None => tls.root_certs(RootCerts::PlatformVerifier),
    };
    match (&s.client_cert_file, &s.client_key_file) {
        (Some(cert_path), Some(key_path)) => {
            let cert_pem = read_pem(cert_path, "pii_vault.client_cert_file")?;
            let chain = certificates(&cert_pem, cert_path, "pii_vault.client_cert_file")?;
            let key_pem = read_pem(key_path, "pii_vault.client_key_file")?;
            let key = PrivateKey::from_pem(&key_pem).map_err(|e| {
                PiiError::Config(format!(
                    "cannot parse pii_vault.client_key_file \"{key_path}\": {e}"
                ))
            })?;
            tls = tls.client_cert(Some(ClientCert::new_with_certs(&chain, key)));
        }
        (None, None) => {}
        _ => {
            return Err(PiiError::Config(
                "pii_vault.client_cert_file and pii_vault.client_key_file must be set together"
                    .into(),
            ))
        }
    }
    // Per-phase timeouts and no global one: with a global timeout ureq would
    // resolve host names on yet another thread. The backend enforces the
    // overall deadline itself (`execute`).
    let phase = Some(s.timeout);
    let config = ureq::Agent::config_builder()
        .timeout_connect(phase)
        .timeout_send_request(phase)
        .timeout_send_body(phase)
        .timeout_recv_response(phase)
        .timeout_recv_body(phase)
        .http_status_as_error(false)
        // Never follow redirects: the X-Vault-Token header would be replayed
        // to whatever host the redirect names.
        .max_redirects(0)
        .max_redirects_will_error(false)
        // Talk to Vault directly; never route the token through a proxy
        // picked up from the server's environment.
        .proxy(None)
        // A backend sends one request at a time: one warm connection is enough.
        .max_idle_connections(2)
        .max_idle_connections_per_host(2)
        .max_idle_age(KEEP_ALIVE)
        .user_agent(concat!("pg_pii_vault/", env!("CARGO_PKG_VERSION")))
        .tls_config(tls.build())
        .build();
    Ok(config.into())
}

fn with_headers<B>(mut rb: ureq::RequestBuilder<B>, req: &Request) -> ureq::RequestBuilder<B> {
    rb = rb.header("X-Vault-Request", "true");
    if let Some(token) = &req.token {
        rb = rb.header("X-Vault-Token", token.as_str());
    }
    if let Some(ns) = &req.namespace {
        rb = rb.header("X-Vault-Namespace", ns.as_str());
    }
    rb
}

fn classify(e: ureq::Error) -> TransportError {
    use std::io::ErrorKind;
    match e {
        ureq::Error::Timeout(_) => TransportError::Timeout,
        ureq::Error::HostNotFound | ureq::Error::ConnectionFailed => {
            TransportError::Connect(e.to_string())
        }
        ureq::Error::Io(ref io)
            if matches!(
                io.kind(),
                ErrorKind::ConnectionRefused
                    | ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::NotConnected
                    | ErrorKind::BrokenPipe
                    | ErrorKind::UnexpectedEof
                    | ErrorKind::TimedOut
            ) =>
        {
            TransportError::Connect(e.to_string())
        }
        other => TransportError::Other(other.to_string()),
    }
}

fn perform(agent: &ureq::Agent, req: Request) -> Result<Response, TransportError> {
    let sent = match req.method {
        Method::Get => with_headers(agent.get(&req.url), &req).call(),
        Method::Delete => with_headers(agent.delete(&req.url), &req).call(),
        Method::Post => with_headers(agent.post(&req.url), &req)
            .header("Content-Type", "application/json")
            .send(req.json_body.as_ref().map_or(&b"{}"[..], |b| b.as_slice())),
    };
    let mut resp = sent.map_err(classify)?;
    let status = resp.status().as_u16();
    let body = resp
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES)
        .read_to_vec()
        .map_err(classify)?;
    Ok(Response {
        status,
        body: Zeroizing::new(body),
    })
}

/// Start `f` on a new thread that has every signal blocked, so that signals
/// aimed at the backend (cancel, terminate, timeouts, latches) are never
/// delivered to it.
fn spawn_signal_free<F>(f: F) -> std::io::Result<()>
where
    F: FnOnce() + Send + 'static,
{
    // SAFETY: plain libc calls on locally owned sigset_t values; the previous
    // mask of the backend thread is restored before returning.
    unsafe {
        let mut all: libc::sigset_t = std::mem::zeroed();
        let mut previous: libc::sigset_t = std::mem::zeroed();
        libc::sigfillset(&mut all);
        libc::pthread_sigmask(libc::SIG_SETMASK, &all, &mut previous);
        let spawned = std::thread::Builder::new()
            .name("pg_pii_vault-http".into())
            .spawn(f);
        libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
        spawned.map(|_| ())
    }
}

/// Execute one request, servicing PostgreSQL interrupts while waiting, for at
/// most `pii_vault.timeout_ms`. A pending cancel/terminate raises the usual
/// PostgreSQL error from here.
pub fn execute(req: Request) -> Result<Result<Response, TransportError>, PiiError> {
    let agent = agent()?;
    let deadline = Instant::now() + config::transport().timeout;
    let live = LIVE_WORKERS.fetch_add(1, Ordering::AcqRel);
    if live >= MAX_LIVE_WORKERS {
        LIVE_WORKERS.fetch_sub(1, Ordering::AcqRel);
        return Err(PiiError::Unavailable(format!(
            "{live} earlier requests of this session to Vault are still running after being \
             cancelled or timing out; try again when they finish (at most pii_vault.timeout_ms)"
        )));
    }
    let slot = WorkerSlot;
    let (tx, rx) = mpsc::sync_channel(1);
    let spawned = spawn_signal_free(move || {
        let _slot = slot;
        let _ = tx.send(perform(&agent, req));
    });
    if let Err(e) = spawned {
        // The closure, and with it the slot, was dropped.
        return Err(PiiError::Unavailable(format!(
            "cannot start HTTP worker thread: {e}"
        )));
    }
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Ok(Err(TransportError::Timeout));
        }
        match rx.recv_timeout(INTERRUPT_POLL.min(deadline - now)) {
            Ok(result) => return Ok(result),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                pgrx::check_for_interrupts!();
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Ok(Err(TransportError::Other(
                    "HTTP worker thread terminated unexpectedly".into(),
                )))
            }
        }
    }
}

/// Sleep for `d`, still reacting to interrupts.
pub fn interruptible_sleep(d: Duration) {
    let deadline = std::time::Instant::now() + d;
    loop {
        pgrx::check_for_interrupts!();
        let now = std::time::Instant::now();
        if now >= deadline {
            return;
        }
        std::thread::sleep((deadline - now).min(INTERRUPT_POLL));
    }
}

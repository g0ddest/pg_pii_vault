//! A small in-process imitation of the Vault Transit API, used to exercise
//! every Vault code path deterministically (including failures) without a
//! real server. It runs on plain threads and never calls into PostgreSQL.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use pgrx::prelude::*;
use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const TOKEN: &str = "fake-root-token";

pub struct FakeKey {
    pub versions: Vec<[u8; 32]>,
    pub exportable: bool,
    pub deletion_allowed: bool,
    pub min_decryption_version: usize,
}

#[derive(Clone, Debug)]
pub struct Recorded {
    pub method: String,
    pub path: String,
    pub token: Option<String>,
    pub namespace: Option<String>,
}

#[derive(Default)]
pub struct State {
    pub keys: HashMap<String, FakeKey>,
    pub requests: Vec<Recorded>,
    /// Statuses returned for the next requests, in order: 404 answers like
    /// Vault does for a missing key (`{"errors":[]}`), the others carry an
    /// error message.
    pub fail_next: VecDeque<u16>,
    /// Raw (status, body) answers for the next requests, e.g. what a proxy
    /// in front of Vault would send. Served before `fail_next`.
    pub raw_next: VecDeque<(u16, String)>,
    /// Secrets engines: (mount path, engine type). Engines other than
    /// "transit" behave like a KV store, as cubbyhole and KV do in Vault.
    pub mounts: Vec<(String, String)>,
    /// Stored by the KV-like engines.
    pub kv: HashMap<String, Vec<u8>>,
    /// (method, path prefix, status): the next request that matches gets
    /// this status with an error body, once.
    pub fail_on: Vec<(String, String, u16)>,
    /// Delete the next key that is deleted, but answer 503 (a lost answer).
    pub lose_delete_answer: bool,
    /// Paths (after /v1/) that answer 403, to imitate a restrictive policy.
    pub forbidden_prefixes: Vec<String>,
    /// Accept connections but never answer.
    pub hang: bool,
    /// Send SIGINT to the backend this long after a request arrives.
    pub sigint_after: Option<Duration>,
    created: u8,
    nonce_counter: u64,
}

pub struct FakeVault {
    pub url: String,
    pub state: Arc<Mutex<State>>,
}

impl FakeVault {
    pub fn start() -> FakeVault {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake vault");
        let url = format!("http://{}", listener.local_addr().expect("local addr"));
        let state = Arc::new(Mutex::new(State {
            mounts: vec![
                ("transit".into(), "transit".into()),
                ("cubbyhole".into(), "cubbyhole".into()),
                ("secret".into(), "kv".into()),
            ],
            ..State::default()
        }));
        let shared = state.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let shared = shared.clone();
                std::thread::spawn(move || handle(stream, shared));
            }
        });
        FakeVault { url, state }
    }

    /// Start a server and point the extension at it. `SET` inside a test is
    /// reverted when the test's transaction is rolled back. The mount is
    /// verified up front, and the recorded requests start empty.
    pub fn configured() -> FakeVault {
        let fake = FakeVault::start();
        Spi::run(&format!("SET pii_vault.url = '{}'", fake.url)).unwrap();
        Spi::run(&format!("SET pii_vault.token = '{TOKEN}'")).unwrap();
        Spi::run("SET pii_vault.mount = 'transit'").unwrap();
        Spi::run("SET pii_vault.max_retries = 0").unwrap();
        Spi::run("SELECT piitext_cache_flush()").unwrap();
        crate::vault::verify_mount(&crate::config::endpoint().unwrap()).unwrap();
        fake.with(|s| s.requests.clear());
        fake
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
        f(&mut self.state.lock().unwrap())
    }

    pub fn has_key(&self, name: &str) -> bool {
        self.with(|s| s.keys.contains_key(name))
    }

    pub fn rotate(&self, name: &str) {
        self.with(|s| {
            let key = s.keys.get_mut(name).expect("key exists");
            let next = [key.versions.len() as u8 + 0x40; 32];
            key.versions.push(next);
        });
    }

    pub fn exportable(&self, name: &str) -> Option<bool> {
        self.with(|s| s.keys.get(name).map(|k| k.exportable))
    }

    pub fn set_min_decryption_version(&self, name: &str, version: usize) {
        self.with(|s| {
            s.keys
                .get_mut(name)
                .expect("key exists")
                .min_decryption_version = version
        });
    }

    pub fn remove_key(&self, name: &str) {
        self.with(|s| s.keys.remove(name));
    }

    pub fn requests(&self) -> Vec<Recorded> {
        self.with(|s| s.requests.clone())
    }

    pub fn count(&self, method: &str, path_prefix: &str) -> usize {
        self.requests()
            .iter()
            .filter(|r| r.method == method && r.path.starts_with(path_prefix))
            .count()
    }
}

fn respond(stream: &mut TcpStream, status: u16, body: &str) {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        307 => "Temporary Redirect",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        412 => "Precondition Failed",
        503 => "Service Unavailable",
        _ => "Status",
    };
    let extra = if status == 307 {
        "Location: http://127.0.0.1:1/elsewhere\r\n"
    } else {
        ""
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.flush();
}

fn errors(msg: &str) -> String {
    serde_json::json!({ "errors": [msg] }).to_string()
}

fn handle(mut stream: TcpStream, state: Arc<Mutex<State>>) {
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(read_half);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() || line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let len = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    let _ = reader.read_exact(&mut body);

    let path = target
        .strip_prefix("/v1/")
        .unwrap_or(&target)
        .split('?')
        .next()
        .unwrap_or("")
        .to_string();
    let (hang, sigint, raw, injected, forbidden) = {
        let mut s = state.lock().unwrap();
        s.requests.push(Recorded {
            method: method.clone(),
            path: path.clone(),
            token: headers.get("x-vault-token").cloned(),
            namespace: headers.get("x-vault-namespace").cloned(),
        });
        let forbidden = s
            .forbidden_prefixes
            .iter()
            .any(|p| path.starts_with(p.as_str()));
        let raw = s.raw_next.pop_front();
        let targeted = s
            .fail_on
            .iter()
            .position(|(m, prefix, _)| *m == method && path.starts_with(prefix.as_str()));
        let injected = if raw.is_some() {
            None
        } else if let Some(i) = targeted {
            Some(s.fail_on.remove(i).2)
        } else {
            s.fail_next.pop_front()
        };
        (s.hang, s.sigint_after, raw, injected, forbidden)
    };
    if let Some(delay) = sigint {
        std::thread::spawn(move || {
            std::thread::sleep(delay);
            // SAFETY: signalling our own process, exactly like pg_cancel_backend().
            unsafe { libc::kill(libc::getpid(), libc::SIGINT) };
        });
    }
    if hang {
        std::thread::sleep(Duration::from_secs(30));
        return;
    }
    if let Some((status, body)) = raw {
        respond(&mut stream, status, &body);
        return;
    }
    if let Some(status) = injected {
        let body = if status == 404 {
            r#"{"errors":[]}"#.to_string()
        } else {
            errors("injected failure")
        };
        respond(&mut stream, status, &body);
        return;
    }
    if path == "sys/health" {
        respond(
            &mut stream,
            200,
            r#"{"initialized":true,"sealed":false,"standby":false,"version":"fake"}"#,
        );
        return;
    }
    if headers.get("x-vault-token").map(String::as_str) != Some(TOKEN) {
        respond(
            &mut stream,
            403,
            &errors("2 errors occurred:\n\t* permission denied\n\t* invalid token\n\n"),
        );
        return;
    }
    if forbidden {
        respond(
            &mut stream,
            403,
            &errors("1 error occurred:\n\t* permission denied\n\n"),
        );
        return;
    }
    let (status, reply) = route(&method, &path, &body, &state);
    respond(&mut stream, status, &reply);
}

fn route(method: &str, path: &str, body: &[u8], state: &Arc<Mutex<State>>) -> (u16, String) {
    let mut s = state.lock().unwrap();
    let segments: Vec<&str> = path.split('/').collect();
    let no_route = || {
        (
            404,
            errors(&format!(
                "no handler for route \"{path}\". route entry not found."
            )),
        )
    };
    if let ["sys", "internal", "ui", "mounts", rest @ ..] = segments.as_slice() {
        let wanted = rest.join("/");
        return match s
            .mounts
            .iter()
            .find(|(m, _)| wanted == *m || wanted.starts_with(&format!("{m}/")))
        {
            Some((m, engine)) => (
                200,
                serde_json::json!({"data": {
                    "type": engine,
                    "path": format!("{m}/"),
                    "accessor": format!("{engine}_fake0001"),
                }})
                .to_string(),
            ),
            None => (
                403,
                errors(&format!(
                    "preflight capability check returned 403, please ensure client's policies grant access to path \"{wanted}/\""
                )),
            ),
        };
    }
    let mount = segments.first().copied().unwrap_or("");
    let engine = s
        .mounts
        .iter()
        .find(|(m, _)| m == mount)
        .map(|(_, e)| e.clone());
    match engine.as_deref() {
        None if !matches!(mount, "auth" | "sys") => return no_route(),
        Some(e) if e != "transit" => {
            // A KV-like engine: reads of missing paths look exactly like
            // Transit's answer for a missing key, and writes succeed.
            return match method {
                "GET" => match s.kv.get(path) {
                    Some(v) => (200, String::from_utf8_lossy(v).into_owned()),
                    None => (404, r#"{"errors":[]}"#.into()),
                },
                "DELETE" => {
                    s.kv.remove(path);
                    (204, String::new())
                }
                _ => {
                    s.kv.insert(path.to_string(), body.to_vec());
                    (204, String::new())
                }
            };
        }
        _ => {}
    }
    match (method, segments.as_slice()) {
        ("GET", ["auth", "token", "lookup-self"]) => (
            200,
            r#"{"data":{"ttl":0,"renewable":false,"policies":["root"]}}"#.into(),
        ),
        ("POST", ["sys", "capabilities-self"]) => {
            let req: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
            let mut out = serde_json::Map::new();
            for p in req["paths"].as_array().cloned().unwrap_or_default() {
                if let Some(p) = p.as_str() {
                    out.insert(p.to_string(), serde_json::json!(["root"]));
                }
            }
            (200, serde_json::Value::Object(out).to_string())
        }
        ("GET", [_mount, "export", "encryption-key", name]) => match s.keys.get(*name) {
            None => (404, r#"{"errors":[]}"#.into()),
            Some(k) if !k.exportable => (400, errors("private key material is not exportable")),
            Some(k) => {
                let mut keys = serde_json::Map::new();
                for (i, v) in k.versions.iter().enumerate() {
                    if i + 1 >= k.min_decryption_version {
                        keys.insert((i + 1).to_string(), serde_json::json!(STANDARD.encode(v)));
                    }
                }
                (
                    200,
                    serde_json::json!({"data": {"name": name, "type": "aes256-gcm96", "keys": keys}})
                        .to_string(),
                )
            }
        },
        ("POST", [_mount, "keys", name]) => {
            if !s.keys.contains_key(*name) {
                s.created = s.created.wrapping_add(1);
                let seed = s.created;
                let mut key = [0u8; 32];
                for (i, b) in key.iter_mut().enumerate() {
                    *b = seed.wrapping_mul(31).wrapping_add(i as u8);
                }
                let req: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
                s.keys.insert(
                    name.to_string(),
                    FakeKey {
                        versions: vec![key],
                        exportable: req["exportable"].as_bool().unwrap_or(false),
                        deletion_allowed: false,
                        min_decryption_version: 1,
                    },
                );
            }
            (200, r#"{"data":{}}"#.into())
        }
        // Transit encrypt: like a policy with "update" but not "create" on
        // transit/encrypt/+, a missing key is refused with 403 (no upsert).
        ("POST", [_mount, "encrypt", name]) => {
            let req: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
            let plaintext = STANDARD
                .decode(req["plaintext"].as_str().unwrap_or(""))
                .unwrap_or_default();
            let aad = STANDARD
                .decode(req["associated_data"].as_str().unwrap_or(""))
                .unwrap_or_default();
            s.nonce_counter += 1;
            let counter = s.nonce_counter;
            let Some(k) = s.keys.get(*name) else {
                return (403, errors("1 error occurred:\n\t* permission denied\n\n"));
            };
            let version = k.versions.len();
            let mut nonce = [0u8; 12];
            nonce[..8].copy_from_slice(&counter.to_be_bytes());
            let sealed = Aes256Gcm::new(&k.versions[version - 1].into())
                .encrypt(
                    &Nonce::from(nonce),
                    Payload {
                        msg: &plaintext,
                        aad: &aad,
                    },
                )
                .unwrap();
            let mut blob = nonce.to_vec();
            blob.extend(sealed);
            let ciphertext = format!("vault:v{version}:{}", STANDARD.encode(blob));
            (
                200,
                serde_json::json!({"data": {"ciphertext": ciphertext, "key_version": version}})
                    .to_string(),
            )
        }
        ("POST", [_mount, "decrypt", name]) => {
            let req: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
            let aad = STANDARD
                .decode(req["associated_data"].as_str().unwrap_or(""))
                .unwrap_or_default();
            let ciphertext = req["ciphertext"].as_str().unwrap_or("").to_string();
            let Some(k) = s.keys.get(*name) else {
                return (400, errors("encryption key not found"));
            };
            let Some(rest) = ciphertext.strip_prefix("vault:v") else {
                return (400, errors("invalid ciphertext: no prefix"));
            };
            let (version, payload) = rest.split_once(':').unwrap_or(("0", ""));
            let version: usize = version.parse().unwrap_or(0);
            if version > k.versions.len() {
                return (400, errors("invalid ciphertext: version is too new"));
            }
            let version = version.max(1);
            if version < k.min_decryption_version {
                return (
                    400,
                    errors("ciphertext or signature version is disallowed by policy (too old)"),
                );
            }
            let blob = STANDARD.decode(payload).unwrap_or_default();
            if blob.len() < 12 {
                return (400, errors("invalid ciphertext: too short"));
            }
            match Aes256Gcm::new(&k.versions[version - 1].into()).decrypt(
                &Nonce::try_from(&blob[..12]).unwrap(),
                Payload {
                    msg: &blob[12..],
                    aad: &aad,
                },
            ) {
                Ok(plain) => (
                    200,
                    serde_json::json!({"data": {"plaintext": STANDARD.encode(plain)}}).to_string(),
                ),
                Err(_) => (400, errors("cipher: message authentication failed")),
            }
        }
        ("POST", [_mount, "keys", name, "config"]) => match s.keys.get_mut(*name) {
            None => (
                400,
                errors(&format!("no existing key named {name} could be found")),
            ),
            Some(k) => {
                let req: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
                if let Some(d) = req["deletion_allowed"].as_bool() {
                    k.deletion_allowed = d;
                }
                if let Some(v) = req["min_decryption_version"].as_u64() {
                    k.min_decryption_version = v as usize;
                }
                (200, r#"{"data":{}}"#.into())
            }
        },
        ("DELETE", [_mount, "keys", name]) => match s.keys.get(*name) {
            None => (
                400,
                errors(&format!(
                    "error deleting policy {name}: could not delete key; not found"
                )),
            ),
            Some(k) if !k.deletion_allowed => (
                400,
                errors(&format!(
                    "error deleting policy {name}: deletion is not allowed for this key"
                )),
            ),
            Some(_) => {
                s.keys.remove(*name);
                if std::mem::take(&mut s.lose_delete_answer) {
                    return (503, errors("the answer was lost"));
                }
                (204, String::new())
            }
        },
        _ => no_route(),
    }
}

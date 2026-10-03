//! Layout of piitext values.
//!
//! The bytes stored for a value are either
//! * **staging** — plaintext UTF-8, not encrypted (the gradual-migration mode), or
//! * **sealed** — a CBOR map with the AES-256-GCM ciphertext and its metadata.
//!
//! A CBOR map starts with a byte in `0xA0..=0xBF`, which can never start a
//! valid UTF-8 string, so the two kinds cannot be confused.
//!
//! Sealed format versions:
//! * **1** (pg_pii_vault 0.0.x): no key version; AAD `col:piitext:id:<hex key id>`.
//!   Decryption tries key version 1 first, then the other versions.
//! * **2** (0.1.0+, `key_mode = export`): records the Vault key version (`kv`)
//!   and binds format version, key id and key version into the AAD.
//! * **3** (0.1.0+, `key_mode = transit`): `c` holds the Vault Transit
//!   ciphertext (`vault:vN:...`), produced and decrypted by Vault itself with
//!   AAD `pg_pii_vault:v3:<hex key id>`; there is no local IV or tag.

use crate::error::PiiError;
use crate::vault::MAX_KEY_ID_LEN;
use crate::MAX_PLAINTEXT_BYTES;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

pub const FORMAT_V1: u8 = 1;
pub const FORMAT_V2: u8 = 2;
pub const FORMAT_V3: u8 = 3;
pub const IV_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// Longest key id of a value written by pg_pii_vault 0.0.x (format 1), which
/// did not limit it. Values written since 0.1.0 use at most `MAX_KEY_ID_LEN`.
pub const MAX_LEGACY_KEY_ID_LEN: usize = 1024;

/// Longest Transit ciphertext in a format 3 value. Vault refuses JSON strings
/// longer than 1 MiB, so it cannot have produced a longer one.
pub const MAX_TRANSIT_CIPHERTEXT_LEN: usize = 1024 * 1024;

/// Largest stored value: a sealed value of `MAX_PLAINTEXT_BYTES` and its header.
pub const MAX_STORED_BYTES: usize = MAX_PLAINTEXT_BYTES + 4096;

/// Prefix of the text representation produced by the type output function.
pub const TEXT_PREFIX: &str = "piitext:";

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PiiSealedData {
    #[serde(rename = "v")]
    pub version: u8,
    #[serde(rename = "k", with = "serde_bytes")]
    pub key_id: Vec<u8>,
    #[serde(rename = "kv", default, skip_serializing_if = "Option::is_none")]
    pub key_version: Option<u32>,
    #[serde(
        rename = "i",
        default,
        with = "serde_bytes",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub iv: Vec<u8>,
    #[serde(
        rename = "t",
        default,
        with = "serde_bytes",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub tag: Vec<u8>,
    #[serde(rename = "c", with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

/// The key version of a Vault Transit ciphertext, if `text` has exactly the
/// shape Vault produces: `vault:v<N>:<padded standard base64>` with N >= 1.
pub fn transit_ciphertext_version(text: &str) -> Option<u32> {
    let (digits, b64) = text.strip_prefix("vault:v")?.split_once(':')?;
    if digits.is_empty() || digits.starts_with('0') || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let version = digits.parse::<u32>().ok()?;
    let body = b64.trim_end_matches('=');
    let valid = !b64.is_empty()
        && b64.len() % 4 == 0
        && b64.len() - body.len() <= 2
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/');
    valid.then_some(version)
}

impl PiiSealedData {
    fn validate(&self) -> Result<(), PiiError> {
        match (self.version, self.key_version) {
            (FORMAT_V1, None) => {}
            (FORMAT_V2 | FORMAT_V3, Some(kv)) if kv >= 1 => {}
            (FORMAT_V1, Some(_)) => {
                return Err(PiiError::Corrupted(
                    "format 1 value must not carry a key version".into(),
                ))
            }
            (FORMAT_V2 | FORMAT_V3, _) => {
                return Err(PiiError::Corrupted(format!(
                    "format {} value has no valid key version",
                    self.version
                )))
            }
            (v, _) => {
                return Err(PiiError::Corrupted(format!(
                    "unsupported format version {v} (written by a newer pg_pii_vault?)"
                )))
            }
        }
        let max_key_id = if self.version == FORMAT_V1 {
            MAX_LEGACY_KEY_ID_LEN
        } else {
            MAX_KEY_ID_LEN
        };
        if self.key_id.is_empty() || self.key_id.len() > max_key_id {
            return Err(PiiError::Corrupted(format!(
                "key id is {} bytes long; format {} allows 1 to {max_key_id} bytes",
                self.key_id.len(),
                self.version
            )));
        }
        if self.version == FORMAT_V3 {
            if !self.iv.is_empty() || !self.tag.is_empty() {
                return Err(PiiError::Corrupted(
                    "format 3 value must not carry an IV or tag".into(),
                ));
            }
            if self.ciphertext.len() > MAX_TRANSIT_CIPHERTEXT_LEN {
                return Err(PiiError::Corrupted(format!(
                    "Vault ciphertext is {} bytes long; at most {MAX_TRANSIT_CIPHERTEXT_LEN} are possible",
                    self.ciphertext.len()
                )));
            }
            let version = std::str::from_utf8(&self.ciphertext)
                .ok()
                .and_then(transit_ciphertext_version)
                .ok_or_else(|| {
                    PiiError::Corrupted("format 3 value does not hold a Vault ciphertext".into())
                })?;
            if Some(version) != self.key_version {
                return Err(PiiError::Corrupted(format!(
                    "format 3 value records key version {} but holds a ciphertext of version {version}",
                    self.key_version.unwrap_or(0)
                )));
            }
            return Ok(());
        }
        if self.ciphertext.len() > MAX_PLAINTEXT_BYTES {
            return Err(PiiError::Corrupted(format!(
                "ciphertext is {} bytes long; values are limited to {MAX_PLAINTEXT_BYTES} bytes",
                self.ciphertext.len()
            )));
        }
        if self.iv.len() != IV_LEN {
            return Err(PiiError::Corrupted(format!(
                "IV is {} bytes, expected {IV_LEN}",
                self.iv.len()
            )));
        }
        if self.tag.len() != TAG_LEN {
            return Err(PiiError::Corrupted(format!(
                "authentication tag is {} bytes, expected {TAG_LEN}",
                self.tag.len()
            )));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum PiiTextContents<'a> {
    Staging(Cow<'a, str>),
    Sealed(PiiSealedData),
}

impl<'a> PiiTextContents<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, PiiError> {
        match bytes.first() {
            Some(0xA0..=0xBF) => {
                let sealed: PiiSealedData = serde_cbor::from_slice(bytes)
                    .map_err(|e| PiiError::Corrupted(format!("cannot decode sealed value: {e}")))?;
                sealed.validate()?;
                Ok(PiiTextContents::Sealed(sealed))
            }
            _ => std::str::from_utf8(bytes)
                .map(|s| PiiTextContents::Staging(Cow::Borrowed(s)))
                .map_err(|_| PiiError::Corrupted("plaintext value is not valid UTF-8".into())),
        }
    }

    /// Parse bytes that enter the database from outside (text or binary
    /// input). Sealed values of format 2 or 3 must also be in the exact
    /// encoding this extension writes, so that no other data can travel
    /// inside them.
    pub fn parse_input(bytes: &'a [u8]) -> Result<Self, PiiError> {
        if bytes.len() > MAX_STORED_BYTES {
            return Err(PiiError::InvalidArgument(format!(
                "value is {} bytes long; piitext values are limited to {MAX_PLAINTEXT_BYTES} bytes",
                bytes.len()
            )));
        }
        let contents = Self::parse(bytes)?;
        if let PiiTextContents::Sealed(sealed) = &contents {
            if sealed.version != FORMAT_V1 && contents.to_bytes() != bytes {
                return Err(PiiError::Corrupted(
                    "sealed value is not in the encoding pg_pii_vault writes".into(),
                ));
            }
        }
        Ok(contents)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            PiiTextContents::Staging(s) => s.as_bytes().to_vec(),
            PiiTextContents::Sealed(data) => {
                serde_cbor::to_vec(data).expect("CBOR encoding of a sealed value cannot fail")
            }
        }
    }
}

/// Text representation: `piitext:` followed by the standard base64 of the
/// stored bytes. Safe for COPY (text and CSV), pg_dump and logical replication.
pub fn encode_text(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(TEXT_PREFIX.len() + bytes.len().div_ceil(3) * 4);
    out.push_str(TEXT_PREFIX);
    STANDARD.encode_string(bytes, &mut out);
    out
}

/// The JSON text form of pg_pii_vault 0.0.x: `{"inner":[<byte>, ...]}`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyJson {
    inner: Vec<u8>,
}

/// Parse the text representation into the value bytes; the flag tells whether
/// they are a plaintext staging value. Also accepts the JSON form written by
/// pg_pii_vault 0.0.x (`{"inner":[...]}`) so old dumps can be restored.
pub fn decode_text(input: &str) -> Result<(Vec<u8>, bool), PiiError> {
    let text = input.trim_matches(|c: char| c.is_ascii_whitespace());
    // Oversized input is refused before it is decoded: its encoded length
    // bounds the memory that decoding would take.
    let too_long = || {
        PiiError::InvalidArgument(format!(
            "piitext input is {} characters long; piitext values are limited to {MAX_PLAINTEXT_BYTES} bytes",
            text.len()
        ))
    };
    let bytes = if let Some(b64) = text.strip_prefix(TEXT_PREFIX) {
        if b64.len() > MAX_STORED_BYTES.div_ceil(3) * 4 {
            return Err(too_long());
        }
        STANDARD
            .decode(b64)
            .map_err(|e| PiiError::InvalidText(format!("bad base64 payload: {e}")))?
    } else if text.starts_with('{') {
        // Up to four characters ("255,") per byte.
        if text.len() > MAX_STORED_BYTES * 4 + 64 {
            return Err(too_long());
        }
        serde_json::from_str::<LegacyJson>(text)
            .map_err(|e| PiiError::InvalidText(format!("bad legacy JSON value: {e}")))?
            .inner
    } else {
        return Err(PiiError::InvalidText(format!(
            "expected a value starting with \"{TEXT_PREFIX}\""
        )));
    };
    let staging = match PiiTextContents::parse_input(&bytes) {
        Ok(contents) => matches!(contents, PiiTextContents::Staging(_)),
        Err(e @ PiiError::InvalidArgument(_)) => return Err(e),
        Err(e) => return Err(PiiError::InvalidText(e.to_string())),
    };
    Ok((bytes, staging))
}

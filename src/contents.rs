use serde::{Deserialize, Serialize};
use std::borrow::Cow;

#[derive(Serialize, Deserialize, Debug)]
pub struct PiiSealedData {
    #[serde(rename = "v")]
    pub version: u8,
    #[serde(rename = "k")]
    pub key_id: Vec<u8>,
    #[serde(rename = "i")]
    pub iv: Vec<u8>,
    #[serde(rename = "t")]
    pub tag: Vec<u8>,
    #[serde(rename = "c")]
    pub ciphertext: Vec<u8>,
}

#[derive(Debug)]
pub enum PiiTextContents<'a> {
    Staging(Cow<'a, str>),
    Sealed(PiiSealedData),
}

// Implement In/Out for Postgres
impl<'a> PiiTextContents<'a> {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        if let Ok(sealed) = serde_cbor::from_slice(bytes) {
            PiiTextContents::Sealed(sealed)
        } else {
            PiiTextContents::Staging(Cow::Owned(String::from_utf8_lossy(bytes).into_owned()))
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            PiiTextContents::Staging(s) => s.as_bytes().to_vec(),
            PiiTextContents::Sealed(data) => serde_cbor::to_vec(data).expect("CBOR serialization failed"),
        }
    }
}

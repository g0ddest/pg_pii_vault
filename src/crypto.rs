use crate::contents::{PiiSealedData, FORMAT_V1, FORMAT_V2, IV_LEN, TAG_LEN};
use crate::error::PiiError;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use zeroize::Zeroizing;

/// Additional authenticated data. It binds the header fields to the
/// ciphertext; it does not bind a value to a particular row (a sealed value
/// copied to another row still decrypts there).
fn aad(format: u8, key_id: &[u8], key_version: u32) -> String {
    match format {
        FORMAT_V1 => format!("col:piitext:id:{}", hex::encode(key_id)),
        _ => format!(
            "pg_pii_vault:v{format}:{}:{key_version}",
            hex::encode(key_id)
        ),
    }
}

/// AAD sent to Vault for format 3 values. It separates this extension's
/// ciphertexts from those of other applications using the same Transit keys,
/// so the database cannot be used to decrypt them.
pub fn transit_aad(key_id: &[u8]) -> String {
    format!("pg_pii_vault:v3:{}", hex::encode(key_id))
}

fn random_iv() -> Result<[u8; IV_LEN], PiiError> {
    let mut iv = [0u8; IV_LEN];
    // SAFETY: the buffer is valid for IV_LEN bytes; pg_strong_random is
    // PostgreSQL's CSPRNG and is called on the backend thread.
    let ok = unsafe { pgrx::pg_sys::pg_strong_random(iv.as_mut_ptr().cast(), IV_LEN) };
    if ok {
        Ok(iv)
    } else {
        Err(PiiError::Unavailable(
            "pg_strong_random() failed to produce an IV".into(),
        ))
    }
}

/// Encrypt `plaintext` with a fresh random 96-bit IV (format 2).
pub fn seal(
    plaintext: &[u8],
    key_id: &[u8],
    key_version: u32,
    key: &[u8; 32],
) -> Result<PiiSealedData, PiiError> {
    let iv = random_iv()?;
    let aad = aad(FORMAT_V2, key_id, key_version);
    let mut ciphertext = Aes256Gcm::new(key.into())
        .encrypt(
            Nonce::from_slice(&iv),
            Payload {
                msg: plaintext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| PiiError::InvalidArgument("value is too large to encrypt".into()))?;
    let tag = ciphertext.split_off(ciphertext.len() - TAG_LEN);
    Ok(PiiSealedData {
        version: FORMAT_V2,
        key_id: key_id.to_vec(),
        key_version: Some(key_version),
        iv: iv.to_vec(),
        tag,
        ciphertext,
    })
}

/// Try to decrypt with one candidate key; `None` when authentication fails
/// (wrong key, wrong key version, or tampered data).
pub fn open(
    sealed: &PiiSealedData,
    key_version: u32,
    key: &[u8; 32],
) -> Option<Zeroizing<Vec<u8>>> {
    let aad = aad(sealed.version, &sealed.key_id, key_version);
    let mut buf = Vec::with_capacity(sealed.ciphertext.len() + TAG_LEN);
    buf.extend_from_slice(&sealed.ciphertext);
    buf.extend_from_slice(&sealed.tag);
    Aes256Gcm::new(key.into())
        .decrypt(
            Nonce::from_slice(&sealed.iv),
            Payload {
                msg: &buf,
                aad: aad.as_bytes(),
            },
        )
        .ok()
        .map(Zeroizing::new)
}

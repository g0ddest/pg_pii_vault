use crate::contents::PiiSealedData;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};

pub fn encrypt(
    plaintext: &str,
    key: &[u8; 32],
    key_id: &[u8],
    context: &str,
) -> Result<PiiSealedData, String> {
    let cipher = Aes256Gcm::new(key.into());
    let mut iv_bytes = [0u8; 12];
    unsafe {
        if !pgrx::pg_sys::pg_strong_random(iv_bytes.as_mut_ptr() as *mut std::ffi::c_void, 12) {
            return Err("Failed to generate random IV".to_string());
        }
    }

    let nonce = Nonce::from_slice(&iv_bytes);
    let payload = Payload {
        msg: plaintext.as_bytes(),
        aad: context.as_bytes(),
    };

    let ciphertext_with_tag = cipher
        .encrypt(nonce, payload)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    // aes-gcm crate appends tag at the end by default if using encrypt
    // but we might want to separate it as per spec
    let tag_pos = ciphertext_with_tag.len() - 16;
    let ciphertext = ciphertext_with_tag[..tag_pos].to_vec();
    let tag = ciphertext_with_tag[tag_pos..].to_vec();

    Ok(PiiSealedData {
        version: 1,
        key_id: key_id.to_vec(),
        iv: iv_bytes.to_vec(),
        tag,
        ciphertext,
    })
}

pub fn decrypt(data: &PiiSealedData, key: &[u8; 32], context: &str) -> Result<String, String> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(&data.iv);

    let mut ciphertext_with_tag = data.ciphertext.clone();
    ciphertext_with_tag.extend_from_slice(&data.tag);

    let payload = Payload {
        msg: &ciphertext_with_tag,
        aad: context.as_bytes(),
    };

    let plaintext_bytes = cipher
        .decrypt(nonce, payload)
        .map_err(|e| format!("Decryption failed: {}", e))?;

    String::from_utf8(plaintext_bytes).map_err(|e| format!("Invalid UTF-8: {}", e))
}

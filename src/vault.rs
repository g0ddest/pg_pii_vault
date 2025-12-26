use crate::{PII_VAULT_MOUNT, PII_VAULT_TOKEN, PII_VAULT_URL};
use base64::{engine::general_purpose, Engine as _};
use serde::Deserialize;

#[derive(Deserialize)]
struct VaultExportResponse {
    data: VaultExportData,
}

#[derive(Deserialize)]
struct VaultExportData {
    keys: std::collections::HashMap<String, String>,
}

pub fn get_key_from_vault(key_id: &[u8]) -> Result<[u8; 32], String> {
    let url_guc = PII_VAULT_URL.get().ok_or("pii_vault.url is not set")?;
    let token_guc = PII_VAULT_TOKEN.get().ok_or("pii_vault.token is not set")?;
    let mount_guc = PII_VAULT_MOUNT.get();

    let url = url_guc
        .to_str()
        .map_err(|e: std::str::Utf8Error| e.to_string())?;
    let token = token_guc
        .to_str()
        .map_err(|e: std::str::Utf8Error| e.to_string())?;
    let mount_str;
    let mount = match &mount_guc {
        Some(m) => {
            mount_str = m.to_str().map_err(|e: std::str::Utf8Error| e.to_string())?;
            mount_str
        }
        None => "transit",
    };

    let key_name = hex::encode(key_id);
    let full_url = format!("{}/v1/{}/export/encryption-key/{}", url, mount, key_name);

    let client = reqwest::blocking::Client::new();
    let resp = client
        .get(&full_url)
        .header("X-Vault-Token", token)
        .send()
        .map_err(|e| format!("Vault request failed: {}", e))?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        // Try to create key if not found
        create_key_in_vault(url, token, mount, &key_name)?;
        // Retry export
        return get_key_from_vault(key_id);
    }

    if !resp.status().is_success() {
        return Err(format!("Vault returned error: {}", resp.status()));
    }

    let export_resp: VaultExportResponse = resp
        .json()
        .map_err(|e| format!("Failed to parse Vault response: {}", e))?;

    // Transit export returns keys in a map, version as key
    let latest_key_base64 = export_resp
        .data
        .keys
        .values()
        .next()
        .ok_or("No key found in Vault response")?;
    let key_bytes = general_purpose::STANDARD
        .decode(latest_key_base64)
        .map_err(|e| format!("Failed to decode key: {}", e))?;

    if key_bytes.len() != 32 {
        return Err(format!("Invalid key length: {}", key_bytes.len()));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    Ok(key)
}

fn create_key_in_vault(url: &str, token: &str, mount: &str, key_name: &str) -> Result<(), String> {
    let full_url = format!("{}/v1/{}/keys/{}", url, mount, key_name);
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(&full_url)
        .header("X-Vault-Token", token)
        .json(&serde_json::json!({
            "type": "aes256-gcm96",
            "exportable": true
        }))
        .send()
        .map_err(|e| format!("Vault create key request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!(
            "Vault create key returned error: {}",
            resp.status()
        ));
    }
    Ok(())
}

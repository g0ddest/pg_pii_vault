use pgrx::guc::{GucContext, GucFlags, GucRegistry, GucSetting};
use pgrx::prelude::*;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::ffi::CStr;
use std::ffi::CString;

mod contents;
mod crypto;
mod vault;
mod cache;
use contents::PiiTextContents;

static PII_VAULT_URL: GucSetting<Option<CString>> = GucSetting::<Option<CString>>::new(None);
static PII_VAULT_TOKEN: GucSetting<Option<CString>> = GucSetting::<Option<CString>>::new(None);
static PII_VAULT_MOUNT: GucSetting<Option<CString>> = GucSetting::<Option<CString>>::new(None);
static PII_VAULT_CACHE_TTL: GucSetting<i32> = GucSetting::<i32>::new(300);

::pgrx::pg_module_magic!(name, version);

#[pg_guard]
pub unsafe extern "C-unwind" fn _PG_init() {
    GucRegistry::define_string_guc(
        CStr::from_bytes_with_nul_unchecked(b"pii_vault.url\0"),
        CStr::from_bytes_with_nul_unchecked(b"Vault server URL\0"),
        CStr::from_bytes_with_nul_unchecked(b"URL of the Hashicorp Vault server\0"),
        &PII_VAULT_URL,
        GucContext::Userset,
        GucFlags::default(),
    );
    GucRegistry::define_string_guc(
        CStr::from_bytes_with_nul_unchecked(b"pii_vault.token\0"),
        CStr::from_bytes_with_nul_unchecked(b"Vault token\0"),
        CStr::from_bytes_with_nul_unchecked(b"Authentication token for Vault\0"),
        &PII_VAULT_TOKEN,
        GucContext::Userset,
        GucFlags::default(),
    );
    GucRegistry::define_string_guc(
        CStr::from_bytes_with_nul_unchecked(b"pii_vault.mount\0"),
        CStr::from_bytes_with_nul_unchecked(b"Vault Transit Mount\0"),
        CStr::from_bytes_with_nul_unchecked(b"Mount path for the Transit engine\0"),
        &PII_VAULT_MOUNT,
        GucContext::Userset,
        GucFlags::default(),
    );
    GucRegistry::define_int_guc(
        CStr::from_bytes_with_nul_unchecked(b"pii_vault.cache_ttl_sec\0"),
        CStr::from_bytes_with_nul_unchecked(b"Cache TTL\0"),
        CStr::from_bytes_with_nul_unchecked(b"Time to live for cached keys in seconds\0"),
        &PII_VAULT_CACHE_TTL,
        0,
        i32::MAX,
        GucContext::Userset,
        GucFlags::default(),
    );
}

#[derive(Debug, Clone, Serialize, Deserialize, PostgresType)]
pub struct PiiText {
    inner: Vec<u8>,
}

// Custom input function - converts text to PiiText
#[pg_extern(immutable, strict, name = "piitext_in_text")]
fn piitext_input(input: &str) -> PiiText {
    PiiText {
        inner: PiiTextContents::Staging(Cow::Borrowed(input)).into(),
    }
}

// Custom output function - converts PiiText to readable text
#[pg_extern(immutable, strict, name = "piitext_out_text")]
fn piitext_output(input: PiiText) -> String {
    let pii = PiiTextContents::from(input.inner.as_slice());
    match pii {
        PiiTextContents::Staging(s) => s.into_owned(),
        PiiTextContents::Sealed(sealed) => {
            let context = format!("col:piitext:id:{}", hex::encode(&sealed.key_id));
            let url = PII_VAULT_URL.get();
            let is_mock = match url {
                Some(ref u) => u.to_str().unwrap_or("").starts_with("mock://"),
                None => false,
            };

            let key = if is_mock {
                Some([0u8; 32])
            } else {
                cache::get_cached_key(&sealed.key_id)
                    .or_else(|| {
                        vault::get_key_from_vault(&sealed.key_id).ok().map(|k| {
                            cache::insert_into_cache(sealed.key_id.clone(), k, PII_VAULT_CACHE_TTL.get() as u64);
                            k
                        })
                    })
            };

            if let Some(k) = key {
                crypto::decrypt(&sealed, &k, &context).unwrap_or_else(|_| "****".to_string())
            } else {
                "****".to_string()
            }
        }
    }
}

// Create implicit casts so piitext behaves like text
extension_sql!(r#"
-- Make casts implicit so SELECT works naturally
CREATE CAST (text AS piitext) WITH FUNCTION piitext_in_text(text) AS IMPLICIT;
CREATE CAST (piitext AS text) WITH FUNCTION piitext_out_text(piitext) AS IMPLICIT;
"#, name = "piitext_casts", requires = [piitext_input, piitext_output]);

#[pg_extern]
fn piitext_debug(input: PiiText) -> String {
    let pii = PiiTextContents::from(input.inner.as_slice());
    format!("{:?}", pii)
}

#[pg_extern]
fn piitext_raw(input: PiiText) -> Vec<u8> {
    input.inner
}

// Encrypt text with specified key_id
#[pg_extern(immutable, strict)]
fn piitext_encrypt(plaintext: &str, key_id_bytes: Vec<u8>) -> PiiText {
    let url = PII_VAULT_URL.get();
    let is_mock = match url {
        Some(ref u) => u.to_str().unwrap_or("").starts_with("mock://"),
        None => false,
    };

    let key = if is_mock {
        [0u8; 32]
    } else {
        match cache::get_cached_key(&key_id_bytes) {
            Some(k) => k,
            None => {
                match vault::get_key_from_vault(&key_id_bytes) {
                    Ok(k) => {
                        cache::insert_into_cache(key_id_bytes.clone(), k, PII_VAULT_CACHE_TTL.get() as u64);
                        k
                    }
                    Err(e) => {
                        pgrx::error!("Vault error: {}", e);
                    }
                }
            }
        }
    };

    let context = format!("col:piitext:id:{}", hex::encode(&key_id_bytes));
    match crypto::encrypt(plaintext, &key, &key_id_bytes, &context) {
        Ok(sealed) => {
            PiiText { inner: PiiTextContents::Sealed(sealed).into() }
        }
        Err(e) => {
            pgrx::error!("Encryption failed: {}", e);
        }
    }
}

// Encrypt or re-encrypt PiiText with specified key_id
// This allows re-encrypting already stored data with a new key
#[pg_extern(immutable, strict, name = "piitext_encrypt_piitext")]
fn piitext_encrypt_from_piitext(input: PiiText, key_id_bytes: Vec<u8>) -> PiiText {
    // First, extract the plaintext from the input
    let plaintext = match PiiTextContents::from(input.inner.as_slice()) {
        PiiTextContents::Staging(s) => s.into_owned(),
        PiiTextContents::Sealed(sealed) => {
            // Decrypt the sealed data first
            let context = format!("col:piitext:id:{}", hex::encode(&sealed.key_id));
            let url = PII_VAULT_URL.get();
            let is_mock = match url {
                Some(ref u) => u.to_str().unwrap_or("").starts_with("mock://"),
                None => false,
            };

            let key = if is_mock {
                Some([0u8; 32])
            } else {
                cache::get_cached_key(&sealed.key_id)
                    .or_else(|| {
                        vault::get_key_from_vault(&sealed.key_id).ok().map(|k| {
                            cache::insert_into_cache(sealed.key_id.clone(), k, PII_VAULT_CACHE_TTL.get() as u64);
                            k
                        })
                    })
            };

            match key {
                Some(k) => {
                    match crypto::decrypt(&sealed, &k, &context) {
                        Ok(p) => p,
                        Err(e) => {
                            pgrx::error!("Decryption failed during re-encryption: {}", e);
                        }
                    }
                }
                None => {
                    pgrx::error!("Key not found for decryption during re-encryption");
                }
            }
        }
    };

    // Now encrypt with the new key_id
    piitext_encrypt(&plaintext, key_id_bytes)
}

#[cfg(any(test, feature = "pg_test"))]
#[pg_schema]
mod tests {
    use crate::{piitext_debug, piitext_output, PiiText};
    use pgrx::prelude::*;

    #[pg_test]
    fn test_piitext_basic() {
        // Базовый тест конвертации текста
        let res = Spi::get_one::<&str>("SELECT piitext_out_text(piitext_in_text('hello'))")
            .expect("SPI failed")
            .expect("Result is null");
        assert_eq!(res, "hello");
    }

    #[pg_test]
    fn test_encryption_with_uuid() {
        Spi::run("SET pii_vault.url = 'mock://localhost';").unwrap();

        // Шифруем данные с UUID как ключом (16 bytes)
        // Используем decode для создания bytea из hex
        let encrypted = Spi::get_one::<PiiText>(
            "SELECT piitext_encrypt('my secret', decode('a0eebc999c0b4ef8bb6d6bb9bd380a11', 'hex'))",
        )
        .expect("SPI failed")
        .expect("Result is null");

        // Расшифровываем обратно
        let decrypted = piitext_output(encrypted);
        assert_eq!(decrypted, "my secret");
    }

    #[pg_test]
    fn test_encryption_with_int() {
        Spi::run("SET pii_vault.url = 'mock://localhost';").unwrap();

        // Шифруем данные с integer как ключом (123 в big-endian = 0x0000007b)
        let encrypted = Spi::get_one::<PiiText>(
            "SELECT piitext_encrypt('int secret', decode('0000007b', 'hex'))",
        )
        .expect("SPI failed")
        .expect("Result is null");

        // Расшифровываем обратно
        let decrypted = piitext_output(encrypted);
        assert_eq!(decrypted, "int secret");
    }

    #[pg_test]
    fn test_debug_output() {
        Spi::run("SET pii_vault.url = 'mock://localhost';").unwrap();

        let encrypted = Spi::get_one::<PiiText>(
            "SELECT piitext_encrypt('test data', decode('0102030405060708090a0b0c0d0e0f10', 'hex'))",
        )
        .expect("SPI failed")
        .expect("Result is null");

        let debug = piitext_debug(encrypted);
        // Проверяем что это Sealed структура
        assert!(debug.contains("Sealed"));
        assert!(debug.contains("version: 1"));
        assert!(debug.contains("key_id"));
    }

    #[pg_test]
    fn test_crypto_shredding_workflow() {
        // Setup mock Vault
        Spi::run("SET pii_vault.url = 'mock://localhost';").unwrap();

        // Create test table
        Spi::run("CREATE TABLE users_test (id INT, secret piitext);").unwrap();

        // Step 1: Insert plain text (staging mode)
        Spi::run("INSERT INTO users_test VALUES (123, piitext_in_text('secret text'));").unwrap();

        // Step 2: Verify plain text is readable
        let plain_result = Spi::get_one::<&str>("SELECT piitext_out_text(secret) FROM users_test WHERE id = 123;")
            .expect("SPI failed")
            .expect("Result is null");
        assert_eq!(plain_result, "secret text");

        // Step 3: Encrypt in place with key_id
        Spi::run("UPDATE users_test SET secret = piitext_encrypt_piitext(secret, decode('0000007b', 'hex')) WHERE id = 123;").unwrap();

        // Step 4: Verify encrypted data is still readable (auto-decrypt)
        let encrypted_result = Spi::get_one::<&str>("SELECT piitext_out_text(secret) FROM users_test WHERE id = 123;")
            .expect("SPI failed")
            .expect("Result is null");
        assert_eq!(encrypted_result, "secret text");

        // Step 5: Verify data is actually encrypted (not staging)
        let debug_result = Spi::get_one::<&str>("SELECT piitext_debug(secret) FROM users_test WHERE id = 123;")
            .expect("SPI failed")
            .expect("Result is null");
        assert!(debug_result.contains("Sealed"));
        assert!(debug_result.contains("key_id"));

        // Cleanup
        Spi::run("DROP TABLE users_test;").unwrap();
    }

    #[pg_test]
    fn test_re_encryption_with_different_key() {
        // Setup mock Vault
        Spi::run("SET pii_vault.url = 'mock://localhost';").unwrap();

        // Create test table and encrypt with first key
        Spi::run("CREATE TABLE reencrypt_test (id INT, data piitext);").unwrap();
        Spi::run("INSERT INTO reencrypt_test VALUES (1, piitext_encrypt('sensitive data', decode('00000001', 'hex')));").unwrap();

        // Verify first encryption
        let debug1 = Spi::get_one::<&str>("SELECT piitext_debug(data) FROM reencrypt_test WHERE id = 1;")
            .expect("SPI failed")
            .expect("Result is null");
        assert!(debug1.contains("key_id: [0, 0, 0, 1]"));

        // Re-encrypt with second key
        Spi::run("UPDATE reencrypt_test SET data = piitext_encrypt_piitext(data, decode('00000002', 'hex')) WHERE id = 1;").unwrap();

        // Verify second encryption
        let debug2 = Spi::get_one::<&str>("SELECT piitext_debug(data) FROM reencrypt_test WHERE id = 1;")
            .expect("SPI failed")
            .expect("Result is null");
        assert!(debug2.contains("key_id: [0, 0, 0, 2]"));

        // Verify plaintext is still the same
        let decrypted = Spi::get_one::<&str>("SELECT piitext_out_text(data) FROM reencrypt_test WHERE id = 1;")
            .expect("SPI failed")
            .expect("Result is null");
        assert_eq!(decrypted, "sensitive data");

        // Cleanup
        Spi::run("DROP TABLE reencrypt_test;").unwrap();
    }
}

#[cfg(test)]
pub mod pg_test {
    pub fn setup(_options: Vec<&str>) {
    }

    #[must_use]
    pub fn postgresql_conf_options() -> Vec<&'static str> {
        vec![
            "pii_vault.url = 'mock://localhost'",
        ]
    }
}

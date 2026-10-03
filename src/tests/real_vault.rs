//! End-to-end tests against a real Vault server. They run only when
//! PII_VAULT_TEST_URL is set (CI starts a Vault dev server), e.g.
//!   PII_VAULT_TEST_URL=http://127.0.0.1:8200 PII_VAULT_TEST_TOKEN=root cargo pgrx test
//! PII_VAULT_TEST_TOKEN is used by the extension in export mode (ideally a
//! token with vault/policies/pg-pii-vault.hcl + pg-pii-vault-shred.hcl),
//! PII_VAULT_TEST_TRANSIT_TOKEN in transit mode (pg-pii-vault-transit.hcl +
//! pg-pii-vault-shred.hcl); both default to PII_VAULT_TEST_TOKEN.
//! PII_VAULT_TEST_ADMIN_TOKEN (defaults to PII_VAULT_TEST_TOKEN) performs the
//! administrative key rotation.

#[pgrx::pg_schema]
mod tests {
    use crate::contents::{FORMAT_V2, FORMAT_V3};
    use crate::keyring;
    use crate::tests::{decrypt, encrypt, sealed, select_bool};
    use pgrx::prelude::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn configure() -> Option<(String, String)> {
        let url = std::env::var("PII_VAULT_TEST_URL").ok()?;
        let token = std::env::var("PII_VAULT_TEST_TOKEN").unwrap_or_else(|_| "root".into());
        let admin = std::env::var("PII_VAULT_TEST_ADMIN_TOKEN").unwrap_or_else(|_| token.clone());
        Spi::run(&format!("SET pii_vault.url = '{url}'")).unwrap();
        Spi::run(&format!("SET pii_vault.token = '{token}'")).unwrap();
        Spi::run("SET pii_vault.mount = 'transit'").unwrap();
        Spi::run("SELECT piitext_cache_flush()").unwrap();
        Some((url, admin))
    }

    /// A key id no other test run has used.
    fn fresh_key_hex() -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("{:032x}{:08x}", nanos, std::process::id())
    }

    /// Every required line of piitext_vault_check() must be ok.
    fn assert_healthy() {
        let problems = Spi::get_one::<String>(
            "SELECT coalesce(string_agg(check_name || ': ' || detail, '; '), '') \
             FROM piitext_vault_check() WHERE required AND NOT ok",
        )
        .unwrap()
        .unwrap();
        assert_eq!(problems, "", "piitext_vault_check() reports problems");
    }

    fn rotate(url: &str, token: &str, key_hex: &str) {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(true)
            .build()
            .into();
        agent
            .post(&format!("{url}/v1/transit/keys/{key_hex}/rotate"))
            .header("X-Vault-Token", token)
            .send_empty()
            .expect("rotate key");
    }

    #[pg_test]
    fn real_vault_full_lifecycle() {
        let Some((url, admin_token)) = configure() else {
            notice!("PII_VAULT_TEST_URL is not set; skipping the real Vault test");
            return;
        };
        let key = fresh_key_hex();

        let first = encrypt("real secret", &key);
        assert_eq!(sealed(&first).key_version, Some(1));
        assert_eq!(decrypt(&first), "real secret");

        rotate(&url, &admin_token, &key);
        Spi::run("SELECT piitext_cache_flush()").unwrap();
        let second = encrypt("after rotation", &key);
        assert_eq!(sealed(&second).key_version, Some(2));
        assert_eq!(decrypt(&first), "real secret");
        let upgraded = crate::piitext_reencrypt(first.clone());
        assert_eq!(sealed(&upgraded).key_version, Some(2));

        assert_healthy();

        // A wrong mount must be an error, never a mask (403 with a
        // least-privilege token, 404 "no handler for route" with a root one).
        Spi::run("SET pii_vault.mount = 'pg-pii-vault-no-such-mount'").unwrap();
        assert!(keyring::open(&sealed(&first)).is_err());
        Spi::run("SET pii_vault.mount = 'transit'").unwrap();
        assert_eq!(decrypt(&first), "real secret");

        assert!(select_bool(&format!(
            "SELECT piitext_shred('\\x{key}'::bytea)"
        )));
        assert_eq!(decrypt(&first), "****");
        assert_eq!(decrypt(&second), "****");
        assert_eq!(decrypt(&upgraded), "****");
        assert!(!select_bool(&format!(
            "SELECT piitext_shred('\\x{key}'::bytea)"
        )));
    }

    #[pg_test]
    fn real_vault_transit_lifecycle() {
        let Some((url, admin_token)) = configure() else {
            notice!("PII_VAULT_TEST_URL is not set; skipping the real Vault transit test");
            return;
        };
        let token = std::env::var("PII_VAULT_TEST_TRANSIT_TOKEN")
            .or_else(|_| std::env::var("PII_VAULT_TEST_TOKEN"))
            .unwrap_or_else(|_| "root".into());
        Spi::run(&format!("SET pii_vault.token = '{token}'")).unwrap();
        Spi::run("SET pii_vault.key_mode = 'transit'").unwrap();
        let key = fresh_key_hex();

        let first = encrypt("transit secret", &key);
        assert_eq!(sealed(&first).version, crate::contents::FORMAT_V3);
        assert_eq!(decrypt(&first), "transit secret");

        rotate(&url, &admin_token, &key);
        let second = encrypt("after rotation", &key);
        assert_eq!(sealed(&second).key_version, Some(2));
        assert_eq!(decrypt(&first), "transit secret");

        assert_healthy();

        // The size limit must fit Vault's default JSON string limit (1 MiB).
        let largest = "x".repeat(crate::MAX_TRANSIT_PLAINTEXT_BYTES);
        let big = crate::PiiText::sealed(
            keyring::seal(&largest, &sealed(&first).key_id).expect("largest transit value"),
        );
        assert_eq!(decrypt(&big).len(), largest.len());

        assert!(select_bool(&format!(
            "SELECT piitext_shred('\\x{key}'::bytea)"
        )));
        assert_eq!(decrypt(&first), "****");
        assert_eq!(decrypt(&second), "****");
        assert_eq!(decrypt(&big), "****");
    }

    /// Switching key modes: both formats stay readable, and re-encryption
    /// moves a value to the current mode. Needs a token allowed to do both
    /// (the admin token), exactly like a real migration.
    #[pg_test]
    fn real_vault_key_mode_migration() {
        let Some((_url, admin_token)) = configure() else {
            notice!("PII_VAULT_TEST_URL is not set; skipping the real Vault migration test");
            return;
        };
        Spi::run(&format!("SET pii_vault.token = '{admin_token}'")).unwrap();
        let key = fresh_key_hex();

        let exported = encrypt("written in export mode", &key);
        assert_eq!(sealed(&exported).version, FORMAT_V2);

        Spi::run("SET pii_vault.key_mode = 'transit'").unwrap();
        assert_eq!(decrypt(&exported), "written in export mode");
        let migrated = crate::piitext_reencrypt(exported.clone());
        assert_eq!(sealed(&migrated).version, FORMAT_V3);
        assert_eq!(decrypt(&migrated), "written in export mode");

        Spi::run("SET pii_vault.key_mode = 'export'").unwrap();
        assert_eq!(decrypt(&migrated), "written in export mode");
        let back = crate::piitext_reencrypt(migrated);
        assert_eq!(sealed(&back).version, FORMAT_V2);

        assert!(select_bool(&format!(
            "SELECT piitext_shred('\\x{key}'::bytea)"
        )));
        assert_eq!(decrypt(&exported), "****");
        assert_eq!(decrypt(&back), "****");
    }
}

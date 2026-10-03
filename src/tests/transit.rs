//! key_mode = transit: Vault encrypts and decrypts (format 3); keys are
//! created non-exportable and never exported.

#[pgrx::pg_schema]
mod tests {
    use crate::contents::FORMAT_V3;
    use crate::error::PiiError;
    use crate::keyring;
    use crate::tests::fake_vault::FakeVault;
    use crate::tests::{decrypt, encrypt, sealed, select_bool};
    use pgrx::prelude::*;

    fn transit_fake() -> FakeVault {
        let fake = FakeVault::configured();
        Spi::run("SET pii_vault.key_mode = 'transit'").unwrap();
        fake
    }

    #[pg_test]
    fn transit_values_are_encrypted_by_vault() {
        let fake = transit_fake();
        let value = encrypt("alice@example.com", "7a01");
        let s = sealed(&value);
        assert_eq!(s.version, FORMAT_V3);
        assert_eq!(s.key_version, Some(1));
        assert!(s.iv.is_empty() && s.tag.is_empty());
        assert!(s.ciphertext.starts_with(b"vault:v1:"));
        assert_eq!(
            fake.exportable("7a01"),
            Some(false),
            "created non-exportable"
        );
        assert_eq!(decrypt(&value), "alice@example.com");
        assert_eq!(
            fake.count("GET", "transit/export"),
            0,
            "keys never leave Vault"
        );
        assert_eq!(
            fake.count("POST", "transit/encrypt/7a01"),
            2,
            "403 on missing key, then retry"
        );
        assert_eq!(fake.count("POST", "transit/decrypt/7a01"), 1);
        assert!(select_bool(
            "SELECT piitext_debug(piitext_encrypt('x', '\\x7a01'::bytea)) LIKE 'Sealed(format=3,%'"
        ));
    }

    #[pg_test]
    fn transit_values_are_never_cached() {
        let fake = transit_fake();
        let value = encrypt("uncached", "7a02");
        for _ in 0..3 {
            assert_eq!(decrypt(&value), "uncached");
        }
        assert_eq!(fake.count("POST", "transit/decrypt/7a02"), 3);
        assert_eq!(crate::cache::len(), 0);
    }

    #[pg_test]
    fn transit_shredded_and_foreign_values_are_masked() {
        let fake = transit_fake();
        let value = encrypt("to be shredded", "7a03");
        assert!(select_bool("SELECT piitext_shred('\\x7a03'::bytea)"));
        assert_eq!(decrypt(&value), "****");

        // A ciphertext made for the same Vault key by another application
        // (different associated data) is not decrypted through the database.
        let mine = encrypt("mine", "7a04");
        let mut foreign = sealed(&mine);
        let other_app = crate::vault::transit_encrypt(
            &crate::config::endpoint().unwrap(),
            &[0x7a, 0x04],
            b"someone else's secret",
            b"other-application",
        )
        .unwrap();
        foreign.ciphertext = other_app.1.into_bytes();
        assert_eq!(decrypt(&crate::PiiText::sealed(foreign)), "****");
        drop(fake);
    }

    #[pg_test]
    fn transit_errors_are_not_masked() {
        let fake = transit_fake();
        let value = encrypt("important", "7a05");
        fake.with(|s| s.fail_next.extend([503]));
        assert!(matches!(
            keyring::open(&sealed(&value)),
            Err(PiiError::Unavailable(_))
        ));
        let mut broken = sealed(&value);
        broken.ciphertext = b"vault:vX:garbage".to_vec();
        assert!(matches!(
            keyring::open(&broken),
            Err(PiiError::Corrupted(_))
        ));
    }

    #[pg_test]
    fn transit_rotation_and_min_decryption_version() {
        let fake = transit_fake();
        let old = encrypt("v1", "7a06");
        fake.rotate("7a06");
        let new = encrypt("v2", "7a06");
        assert_eq!(sealed(&new).key_version, Some(2));
        assert_eq!(decrypt(&old), "v1");
        let upgraded = crate::piitext_reencrypt(old.clone());
        assert_eq!(sealed(&upgraded).key_version, Some(2));
        fake.set_min_decryption_version("7a06", 2);
        assert_eq!(
            decrypt(&old),
            "****",
            "versions below min_decryption_version are gone"
        );
        assert_eq!(decrypt(&upgraded), "v1");
    }

    #[pg_test]
    fn transit_and_export_values_coexist_and_migrate() {
        let fake = FakeVault::configured();
        let exported = encrypt("from export mode", "7a07");
        assert_eq!(sealed(&exported).version, crate::contents::FORMAT_V2);
        Spi::run("SET pii_vault.key_mode = 'transit'").unwrap();
        assert_eq!(
            decrypt(&exported),
            "from export mode",
            "old mode stays readable"
        );
        let migrated = crate::piitext_reencrypt(exported);
        assert_eq!(sealed(&migrated).version, FORMAT_V3);
        Spi::run("SET pii_vault.key_mode = 'export'").unwrap();
        assert_eq!(decrypt(&migrated), "from export mode");
        drop(fake);
    }

    #[pg_test]
    fn transit_value_size_is_limited() {
        let fake = transit_fake();
        let limit = crate::MAX_TRANSIT_PLAINTEXT_BYTES;
        let largest = "a".repeat(limit);
        let value = crate::PiiText::sealed(keyring::seal(&largest, &[0x7a, 0x09]).unwrap());
        assert_eq!(decrypt(&value).len(), limit);
        match keyring::seal(&"a".repeat(limit + 1), &[0x7a, 0x09]) {
            Err(PiiError::InvalidArgument(msg)) => {
                assert!(msg.contains("key_mode = transit"), "{msg}")
            }
            other => panic!("expected a size error, got {:?}", other.err()),
        }
        assert_eq!(
            fake.count("POST", "transit/encrypt/7a09"),
            2,
            "an oversized value is never sent to Vault"
        );
    }

    #[pg_test]
    fn transit_wrong_mount_is_an_error_not_a_mask() {
        let _fake = transit_fake();
        let value = encrypt("still here", "7a0a");
        // No engine mounted there: Vault refuses to describe the mount.
        Spi::run("SET pii_vault.mount = 'transit-typo'").unwrap();
        assert!(matches!(
            keyring::open(&sealed(&value)),
            Err(PiiError::PermissionDenied(_))
        ));
        assert!(matches!(
            keyring::seal("x", &[0x7a, 0x0a]),
            Err(PiiError::PermissionDenied(_))
        ));
        // Another engine, which would answer like Transit for a missing key.
        Spi::run("SET pii_vault.mount = 'cubbyhole'").unwrap();
        assert!(matches!(
            keyring::open(&sealed(&value)),
            Err(PiiError::Config(_))
        ));
        Spi::run("SET pii_vault.mount = 'transit'").unwrap();
        assert_eq!(decrypt(&value), "still here");
    }

    #[pg_test]
    fn transit_auto_create_can_be_disabled() {
        let fake = transit_fake();
        Spi::run("SET pii_vault.auto_create_keys = off").unwrap();
        assert!(matches!(
            keyring::seal("x", &[0x7a, 0x08]),
            Err(PiiError::PermissionDenied(_))
        ));
        assert!(!fake.has_key("7a08"));
    }

    #[pg_test]
    fn transit_vault_check_reports_mode_specific_policy() {
        let _fake = transit_fake();
        let names: Vec<(String, bool)> = Spi::connect(|client| {
            client
                .select(
                    "SELECT check_name, ok FROM piitext_vault_check()",
                    None,
                    &[],
                )
                .unwrap()
                .map(|r| {
                    (
                        r.get::<String>(1).unwrap().unwrap(),
                        r.get::<bool>(2).unwrap().unwrap(),
                    )
                })
                .collect()
        });
        let find = |n: &str| names.iter().find(|r| r.0 == n).map(|r| r.1);
        assert_eq!(find("key_access"), Some(true));
        assert_eq!(find("policy_encrypt"), Some(true));
        assert_eq!(find("policy_decrypt"), Some(true));
        assert_eq!(find("policy_export"), None, "not needed in transit mode");
        // The fake grants everything ("root"), so it can export: flagged,
        // but only as advice.
        assert_eq!(find("policy_no_export"), Some(false));
        assert!(select_bool(
            "SELECT bool_and(ok) FROM piitext_vault_check() WHERE required"
        ));
    }

    #[pg_test]
    fn transit_values_of_a_recreated_key_are_masked() {
        let fake = transit_fake();
        let _v1 = encrypt("version 1", "7a0b");
        fake.rotate("7a0b");
        let v2 = encrypt("version 2", "7a0b");
        assert_eq!(sealed(&v2).key_version, Some(2));
        // Shredded by another cluster, then created again for new data.
        fake.remove_key("7a0b");
        let fresh = encrypt("new data", "7a0b");
        assert_eq!(sealed(&fresh).key_version, Some(1));
        // Vault: "invalid ciphertext: version is too new".
        assert_eq!(decrypt(&v2), "****");
        assert_eq!(decrypt(&fresh), "new data");
    }

    #[pg_test]
    fn transit_only_exact_vault_answers_count() {
        let fake = transit_fake();
        let value = encrypt("guarded", "7a0c");
        for body in [
            "<html>400 Bad Request: message authentication failed</html>",
            "{\"message\":\"encryption key not found in gateway keystore\"}",
            "{\"errors\":[\"encryption key not found\"],\"warnings\":[]}",
        ] {
            fake.with(|s| s.raw_next.push_back((400, body.to_string())));
            assert!(
                keyring::open(&sealed(&value)).is_err(),
                "{body} must be an error"
            );
        }
        assert_eq!(decrypt(&value), "guarded");
    }

    #[pg_test]
    fn transit_ciphertext_cannot_inject_into_the_request() {
        let _fake = transit_fake();
        let value = encrypt("x", "7a0d");
        let mut crafted = sealed(&value);
        crafted.ciphertext =
            br#"vault:v1:AAAA","batch_input":[{"ciphertext":"vault:v1:AAAA"}],"x":"="#.to_vec();
        let bytes = serde_cbor::to_vec(&crafted).unwrap();
        assert!(matches!(
            crate::contents::PiiTextContents::parse(&bytes),
            Err(PiiError::Corrupted(_))
        ));
        let text = crate::contents::encode_text(&bytes);
        assert!(crate::contents::decode_text(&text).is_err());
    }
}

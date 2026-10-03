#[pgrx::pg_schema]
mod tests {
    use crate::cache::{self, KeySet, Lookup};
    use crate::config;
    use crate::error::PiiError;
    use crate::keyring;
    use crate::tests::fake_vault::{FakeKey, FakeVault, TOKEN};
    use crate::tests::{decrypt, encrypt, sealed, select_bool};
    use pgrx::prelude::*;
    use std::time::{Duration, Instant};
    use zeroize::Zeroizing;

    #[pg_test]
    fn vault_encrypt_creates_the_key_and_decrypts() {
        let fake = FakeVault::configured();
        let value = encrypt("alice@example.com", "0000007b");
        assert!(fake.has_key("0000007b"));
        assert_eq!(fake.count("POST", "transit/keys/0000007b"), 1);
        assert_eq!(
            fake.count("GET", "transit/export/encryption-key/0000007b"),
            2
        );
        assert_eq!(decrypt(&value), "alice@example.com");
        assert!(fake
            .requests()
            .iter()
            .all(|r| r.token.as_deref() == Some(TOKEN)));
    }

    #[pg_test]
    fn vault_decryption_never_creates_keys() {
        let fake = FakeVault::configured();
        let value = encrypt("bob", "0b0b");
        fake.remove_key("0b0b");
        cache::flush();
        assert_eq!(decrypt(&value), "****", "a deleted key means shredded data");
        assert!(!fake.has_key("0b0b"), "reading must not resurrect the key");
        assert_eq!(
            fake.count("POST", "transit/keys/0b0b"),
            1,
            "only the original create"
        );
    }

    #[pg_test]
    fn vault_outage_is_an_error_not_a_mask() {
        let fake = FakeVault::configured();
        let value = encrypt("carol", "0c0c");
        cache::flush();
        fake.with(|s| s.fail_next.extend([503]));
        match keyring::open(&sealed(&value)) {
            Err(PiiError::Unavailable(msg)) => assert!(msg.contains("503"), "{msg}"),
            other => panic!("expected Unavailable, got {:?}", other.err()),
        }
    }

    #[pg_test]
    fn vault_transient_failures_are_retried() {
        let fake = FakeVault::configured();
        Spi::run("SET pii_vault.max_retries = 3").unwrap();
        let value = encrypt("dave", "0d0d");
        cache::flush();
        fake.with(|s| s.fail_next.extend([503, 429, 412]));
        assert_eq!(decrypt(&value), "dave");
        assert_eq!(
            fake.count("GET", "transit/export/encryption-key/0d0d"),
            2 + 4
        );
    }

    #[pg_test]
    fn vault_permission_denied_is_an_error() {
        let fake = FakeVault::configured();
        let value = encrypt("erin", "0e0e");
        cache::flush();
        Spi::run("SET pii_vault.token = 'wrong-token'").unwrap();
        assert!(matches!(
            keyring::open(&sealed(&value)),
            Err(PiiError::PermissionDenied(_))
        ));
        drop(fake);
    }

    #[pg_test]
    fn vault_requests_time_out() {
        let fake = FakeVault::configured();
        Spi::run("SET pii_vault.timeout_ms = 300").unwrap();
        fake.with(|s| s.hang = true);
        let started = Instant::now();
        match keyring::seal("x", &[0x0f]) {
            Err(PiiError::Unavailable(msg)) => assert!(msg.contains("timed out"), "{msg}"),
            other => panic!("expected a timeout, got {:?}", other.err()),
        }
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[pg_test(error = "canceling statement due to user request")]
    fn vault_wait_honours_query_cancel() {
        let fake = FakeVault::configured();
        Spi::run("SET pii_vault.timeout_ms = 20000").unwrap();
        fake.with(|s| {
            s.hang = true;
            s.sigint_after = Some(Duration::from_millis(300));
        });
        let _ = keyring::seal("x", &[0x10]);
    }

    #[pg_test]
    fn vault_rotation_uses_the_latest_version_and_keeps_old_values() {
        let fake = FakeVault::configured();
        let old = encrypt("written under v1", "1111");
        assert_eq!(sealed(&old).key_version, Some(1));
        fake.rotate("1111");
        cache::flush();
        let new = encrypt("written under v2", "1111");
        assert_eq!(sealed(&new).key_version, Some(2));
        assert_eq!(decrypt(&old), "written under v1");
        assert_eq!(decrypt(&new), "written under v2");
        let upgraded = crate::piitext_reencrypt(old);
        assert_eq!(sealed(&upgraded).key_version, Some(2));
        assert_eq!(decrypt(&upgraded), "written under v1");
    }

    #[pg_test]
    fn vault_stale_cache_is_refreshed() {
        let fake = FakeVault::configured();
        fake.with(|s| {
            s.keys.insert(
                "2222".into(),
                FakeKey {
                    versions: vec![[1u8; 32], [2u8; 32]],
                    exportable: true,
                    deletion_allowed: false,
                    min_decryption_version: 1,
                },
            )
        });
        let v2 = encrypt("fresh", "2222");
        assert_eq!(sealed(&v2).key_version, Some(2));
        // Pretend this backend cached the key before the rotation.
        let scope = config::endpoint().unwrap().scope();
        let stale = KeySet::new(vec![(1, Zeroizing::new([1u8; 32]))]).unwrap();
        cache::flush();
        assert!(cache::put(
            &scope,
            &[0x22, 0x22],
            Some(std::sync::Arc::new(stale)),
            crate::shared::generation()
        ));
        assert_eq!(decrypt(&v2), "fresh", "missing version triggers a refetch");
    }

    #[pg_test]
    fn vault_recreated_key_is_picked_up() {
        let fake = FakeVault::configured();
        let _warm = encrypt("warm the cache", "2323");
        // Another cluster shreds the key and a new one with the same name is
        // created; this backend still caches the old one.
        fake.remove_key("2323");
        Spi::run("SET pii_vault.cache_ttl_sec = 300").unwrap();
        let fresh_key = [9u8; 32];
        fake.with(|s| {
            s.keys.insert(
                "2323".into(),
                FakeKey {
                    versions: vec![fresh_key],
                    exportable: true,
                    deletion_allowed: false,
                    min_decryption_version: 1,
                },
            )
        });
        let other = crate::crypto::seal(b"new owner", &[0x23, 0x23], 1, &fresh_key).unwrap();
        let value = crate::PiiText::sealed(other);
        assert_eq!(
            decrypt(&value),
            "new owner",
            "auth failure with a cached key triggers a refetch"
        );
    }

    #[pg_test]
    fn vault_shred_deletes_the_key_and_masks_values() {
        let fake = FakeVault::configured();
        let before = encrypt("old life", "3333");
        let published = crate::shared::generation().key_seq;
        assert!(select_bool("SELECT piitext_shred('\\x3333'::bytea)"));
        assert!(!fake.has_key("3333"));
        assert!(
            crate::shared::generation().key_seq > published,
            "all backends drop their copy of the key"
        );
        assert_eq!(decrypt(&before), "****");
        assert!(
            !select_bool("SELECT piitext_shred('\\x3333'::bytea)"),
            "already gone"
        );

        let after = encrypt("new life", "3333");
        assert!(fake.has_key("3333"), "a new key is created for new data");
        assert_eq!(decrypt(&after), "new life");
        assert_eq!(decrypt(&before), "****", "old data stays shredded");
    }

    #[pg_test(
        error = "encryption key not found in Vault: 3434 (the value was crypto-shredded and cannot be re-encrypted)"
    )]
    fn vault_shredded_values_cannot_be_reencrypted() {
        let fake = FakeVault::configured();
        let value = encrypt("gone", "3434");
        fake.remove_key("3434");
        cache::flush();
        let _ = crate::piitext_reencrypt(value);
    }

    #[pg_test]
    fn vault_namespace_header_is_sent() {
        let fake = FakeVault::configured();
        Spi::run("SET pii_vault.namespace = 'team-a/prod'").unwrap();
        let _ = encrypt("ns", "4545");
        let requests = fake.requests();
        assert!(!requests.is_empty());
        assert!(requests
            .iter()
            .all(|r| r.namespace.as_deref() == Some("team-a/prod")));
    }

    #[pg_test]
    fn vault_token_file_is_read() {
        let fake = FakeVault::configured();
        let path = std::env::temp_dir().join(format!("pg_pii_vault_token_{}", std::process::id()));
        std::fs::write(&path, format!("{TOKEN}\n")).unwrap();
        Spi::run("SET pii_vault.token = ''").unwrap();
        Spi::run(&format!("SET pii_vault.token_file = '{}'", path.display())).unwrap();
        let value = encrypt("from file", "5656");
        assert_eq!(decrypt(&value), "from file");
        std::fs::remove_file(&path).unwrap();
        cache::flush();
        assert!(matches!(
            keyring::open(&sealed(&value)),
            Err(PiiError::Config(_))
        ));
        drop(fake);
    }

    #[pg_test]
    fn vault_auto_create_can_be_disabled() {
        let fake = FakeVault::configured();
        Spi::run("SET pii_vault.auto_create_keys = off").unwrap();
        assert!(matches!(
            keyring::seal("x", &[0x57]),
            Err(PiiError::KeyNotFound(_))
        ));
        assert!(!fake.has_key("57"));
    }

    #[pg_test]
    fn vault_key_provisioned_by_someone_else_when_create_is_denied() {
        let fake = FakeVault::configured();
        // The policy does not allow creating keys (403), but by then another
        // process has provisioned the key: use it instead of failing.
        fake.with(|s| {
            s.keys.insert(
                "5858".into(),
                FakeKey {
                    versions: vec![[5u8; 32]],
                    exportable: true,
                    deletion_allowed: false,
                    min_decryption_version: 1,
                },
            );
            s.fail_next.extend([404, 403]);
        });
        let value = encrypt("raced", "5858");
        assert_eq!(decrypt(&value), "raced");
    }

    #[pg_test]
    fn vault_redirects_are_not_followed() {
        let fake = FakeVault::configured();
        fake.with(|s| s.fail_next.extend([307]));
        match keyring::seal("x", &[0x59]) {
            Err(PiiError::Vault(msg)) => assert!(msg.contains("redirect"), "{msg}"),
            other => panic!("expected a redirect error, got {:?}", other.err()),
        }
        assert_eq!(fake.requests().len(), 1, "the Location was not followed");
    }

    #[pg_test]
    fn vault_non_exportable_key_is_an_error() {
        let fake = FakeVault::configured();
        fake.with(|s| {
            s.keys.insert(
                "6060".into(),
                FakeKey {
                    versions: vec![[6u8; 32]],
                    exportable: false,
                    deletion_allowed: false,
                    min_decryption_version: 1,
                },
            )
        });
        match keyring::seal("x", &[0x60, 0x60]) {
            Err(PiiError::Vault(msg)) => assert!(msg.contains("not exportable"), "{msg}"),
            other => panic!("expected an export error, got {:?}", other.err()),
        }
    }

    #[pg_test]
    fn vault_cache_serves_repeated_reads_and_is_bounded() {
        let fake = FakeVault::configured();
        let value = encrypt("cached", "6161");
        let exports = fake.count("GET", "transit/export/encryption-key/6161");
        for _ in 0..5 {
            assert_eq!(decrypt(&value), "cached");
        }
        assert_eq!(
            fake.count("GET", "transit/export/encryption-key/6161"),
            exports,
            "served from cache"
        );

        Spi::run("SET pii_vault.cache_max_entries = 10").unwrap();
        cache::flush();
        for i in 0..40u8 {
            let _ = encrypt("bounded", &format!("70{i:02x}"));
            assert!(cache::len() <= 10, "cache grew to {}", cache::len());
        }

        Spi::run("SET pii_vault.cache_ttl_sec = 0").unwrap();
        cache::flush();
        let _ = encrypt("uncached", "6262");
        assert_eq!(cache::len(), 0, "ttl 0 disables caching");
    }

    #[pg_test]
    fn vault_cache_is_scoped_to_the_endpoint() {
        let first = FakeVault::configured();
        let value = encrypt("belongs to the first vault", "6363");
        assert!(first.has_key("6363"));
        let second = FakeVault::configured();
        // Same key id, different Vault: the cached key must not be reused.
        assert_eq!(decrypt(&value), "****");
        assert!(!second.has_key("6363"));
    }

    /// (check_name, ok, required, detail) rows of piitext_vault_check().
    fn vault_check_rows() -> Vec<(String, bool, bool, String)> {
        Spi::connect(|client| {
            client
                .select(
                    "SELECT check_name, ok, required, detail FROM piitext_vault_check()",
                    None,
                    &[],
                )
                .unwrap()
                .map(|row| {
                    (
                        row.get::<String>(1).unwrap().unwrap(),
                        row.get::<bool>(2).unwrap().unwrap(),
                        row.get::<bool>(3).unwrap().unwrap(),
                        row.get::<String>(4).unwrap().unwrap(),
                    )
                })
                .collect::<Vec<_>>()
        })
    }

    fn healthy() -> bool {
        select_bool("SELECT bool_and(ok) FROM piitext_vault_check() WHERE required")
    }

    #[pg_test]
    fn vault_check_reports_the_deployment() {
        let fake = FakeVault::configured();
        let rows = vault_check_rows();
        let ok = |name: &str| rows.iter().find(|r| r.0 == name).map(|r| r.1);
        let required = |name: &str| rows.iter().find(|r| r.0 == name).map(|r| r.2);
        assert_eq!(ok("shared_preload_libraries"), Some(true));
        assert_eq!(ok("token"), Some(true));
        assert_eq!(ok("endpoint"), Some(true));
        assert_eq!(
            ok("tls"),
            Some(true),
            "plain http to a loopback address is acceptable"
        );
        assert_eq!(ok("vault_reachable"), Some(true));
        assert_eq!(ok("transit_mount"), Some(true));
        assert_eq!(ok("key_access"), Some(true));
        assert_eq!(ok("token_valid"), Some(true));
        assert_eq!(ok("policy_export"), Some(true));
        assert_eq!(ok("policy_create_keys"), Some(true));
        assert_eq!(ok("policy_shred"), Some(true));
        for name in [
            "transit_mount",
            "key_access",
            "token_valid",
            "policy_export",
        ] {
            assert_eq!(required(name), Some(true), "{name}");
        }
        for name in ["tls", "policy_shred"] {
            assert_eq!(required(name), Some(false), "{name} is advisory");
        }
        assert!(healthy());
        assert!(
            rows.iter().all(|r| !r.3.contains(TOKEN)),
            "never print the token"
        );
        assert!(
            fake.requests()
                .iter()
                .all(|r| !r.path.contains("/keys/") || r.method == "GET"),
            "the check never creates, changes or deletes a key"
        );
        assert!(!fake.has_key("pg-pii-vault-probe"));
    }

    #[pg_test]
    fn vault_check_works_without_the_optional_policy_rules() {
        let fake = FakeVault::configured();
        fake.with(|s| {
            s.forbidden_prefixes = vec![
                "auth/token/lookup-self".into(),
                "sys/capabilities-self".into(),
            ]
        });
        let rows = vault_check_rows();
        let row = |name: &str| rows.iter().find(|r| r.0 == name).cloned().unwrap();
        assert!(
            row("key_access").1,
            "the functional probe needs neither rule"
        );
        let token_valid = row("token_valid");
        assert!(!token_valid.1 && !token_valid.2, "unknown, hence advisory");
        let policy = row("policy");
        assert!(!policy.1 && !policy.2);
        assert!(
            healthy(),
            "optional rules do not make the deployment unhealthy"
        );
    }

    #[pg_test]
    fn vault_check_detects_an_invalid_token() {
        let _fake = FakeVault::configured();
        Spi::run("SET pii_vault.token = 'expired-token'").unwrap();
        let rows = vault_check_rows();
        let row = |name: &str| rows.iter().find(|r| r.0 == name).cloned().unwrap();
        let token_valid = row("token_valid");
        assert!(!token_valid.1 && token_valid.2, "{token_valid:?}");
        assert!(token_valid.3.contains("invalid token"), "{token_valid:?}");
        assert!(
            !token_valid.3.contains('\n') && !token_valid.3.contains('\t'),
            "Vault's multi-line error text is flattened: {token_valid:?}"
        );
        assert!(!row("key_access").1);
        assert!(!healthy());
    }

    #[pg_test]
    fn vault_check_detects_a_wrong_mount() {
        let _fake = FakeVault::configured();
        Spi::run("SET pii_vault.mount = 'transit-typo'").unwrap();
        let rows = vault_check_rows();
        let row = |name: &str| rows.iter().find(|r| r.0 == name).cloned().unwrap();
        let mount = row("transit_mount");
        assert!(!mount.1 && mount.2, "{mount:?}");
        assert!(mount.3.contains("pii_vault.mount"), "{mount:?}");
        let key_access = row("key_access");
        assert!(!key_access.1 && key_access.2, "{key_access:?}");
        assert!(!healthy());
    }

    #[pg_test]
    fn vault_check_knows_when_key_creation_is_not_needed() {
        let fake = FakeVault::configured();
        Spi::run("SET pii_vault.auto_create_keys = off").unwrap();
        let rows = vault_check_rows();
        let create = rows
            .iter()
            .find(|r| r.0 == "policy_create_keys")
            .cloned()
            .unwrap();
        assert!(!create.2, "advisory when keys are provisioned elsewhere");
        assert!(create.3.contains("auto_create_keys is off"), "{create:?}");
        drop(fake);
    }

    #[pg_test]
    fn vault_wrong_mount_is_an_error_not_a_mask() {
        let fake = FakeVault::configured();
        let value = encrypt("still here", "6464");
        // A typo in pii_vault.mount: Vault refuses to describe the mount.
        Spi::run("SET pii_vault.mount = 'transit-typo'").unwrap();
        match keyring::open(&sealed(&value)) {
            Err(PiiError::PermissionDenied(msg)) => {
                assert!(msg.contains("pii_vault.mount \"transit-typo\""), "{msg}")
            }
            other => panic!("expected an error, got {:?}", other.err()),
        }
        assert!(matches!(
            keyring::seal("x", &[0x64, 0x64]),
            Err(PiiError::PermissionDenied(_))
        ));
        assert!(matches!(
            keyring::shred(&[0x64, 0x64]),
            Err(PiiError::PermissionDenied(_))
        ));
        assert!(fake.has_key("6464"), "nothing was deleted");
        Spi::run("SET pii_vault.mount = 'transit'").unwrap();
        assert_eq!(decrypt(&value), "still here");
    }

    #[pg_test]
    fn vault_foreign_404_is_an_error_not_a_mask() {
        let fake = FakeVault::configured();
        let value = encrypt("behind a proxy", "6565");
        for body in [
            "<html><body>404 Not Found</body></html>",
            r#"{"request_id":"x","data":null,"warnings":["Invalid path for a versioned K/V secrets engine."]}"#,
            "",
        ] {
            cache::flush();
            fake.with(|s| s.raw_next.push_back((404, body.to_string())));
            match keyring::open(&sealed(&value)) {
                Err(PiiError::Vault(msg)) => assert!(msg.contains("404"), "{msg}"),
                other => panic!("expected an error for {body:?}, got {:?}", other.err()),
            }
        }
        assert_eq!(decrypt(&value), "behind a proxy");
    }

    #[pg_test]
    fn vault_wrong_key_type_is_rejected() {
        let fake = FakeVault::configured();
        fake.with(|s| {
            s.raw_next.push_back((
                200,
                r#"{"data":{"name":"6666","type":"chacha20-poly1305","keys":{"1":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}}"#.into(),
            ))
        });
        match keyring::seal("x", &[0x66, 0x66]) {
            Err(PiiError::Vault(msg)) => assert!(msg.contains("chacha20-poly1305"), "{msg}"),
            other => panic!("expected a key type error, got {:?}", other.err()),
        }
    }

    #[pg_test]
    fn vault_error_text_is_one_line() {
        let fake = FakeVault::configured();
        let value = encrypt("x", "6767");
        cache::flush();
        Spi::run("SET pii_vault.token = 'expired-token'").unwrap();
        match keyring::open(&sealed(&value)) {
            Err(PiiError::PermissionDenied(msg)) => {
                assert!(msg.contains("invalid token"), "{msg}");
                assert!(!msg.contains('\n') && !msg.contains('\t'), "{msg:?}");
            }
            other => panic!("expected PermissionDenied, got {:?}", other.err()),
        }
        drop(fake);
    }

    #[pg_test]
    fn vault_denied_statements_are_counted() {
        use crate::shared::{local_value, Counter};
        let before = (
            local_value(Counter::VaultDenied),
            local_value(Counter::VaultErrors),
        );
        PiiError::PermissionDenied("x".into()).record();
        PiiError::Unavailable("x".into()).record();
        PiiError::KeyNotFound("x".into()).record();
        assert_eq!(local_value(Counter::VaultDenied), before.0 + 1);
        assert_eq!(local_value(Counter::VaultErrors), before.1);
    }

    #[pg_test]
    fn vault_mount_must_be_a_transit_engine() {
        let fake = FakeVault::configured();
        let value = encrypt("kept safe", "6868");
        // cubbyhole and KV answer reads of missing paths exactly like
        // Transit answers for a missing key, and accept writes.
        for (mount, expected) in [
            ("cubbyhole", "is a cubbyhole secrets engine, not Transit"),
            ("secret", "is a kv secrets engine, not Transit"),
            ("secret/data", "is not the mount point of a secrets engine"),
            ("transit/keys", "is not the mount point of a secrets engine"),
        ] {
            Spi::run(&format!("SET pii_vault.mount = '{mount}'")).unwrap();
            for outcome in [
                keyring::open(&sealed(&value)).map(|_| ()),
                keyring::seal("x", &[0x68, 0x68]).map(|_| ()),
                keyring::shred(&[0x68, 0x68]).map(|_| ()),
            ] {
                match outcome {
                    Err(PiiError::Config(msg)) => assert!(msg.contains(expected), "{msg}"),
                    other => panic!("{mount}: expected a configuration error, got {other:?}"),
                }
            }
        }
        assert!(
            fake.with(|s| s.kv.is_empty()),
            "nothing was written to another engine"
        );
        Spi::run("SET pii_vault.mount = 'transit'").unwrap();
        assert_eq!(decrypt(&value), "kept safe");
        assert!(fake.has_key("6868"), "the key was not deleted");
    }

    #[pg_test]
    fn vault_mount_accessor_can_be_pinned() {
        let _fake = FakeVault::configured();
        let value = encrypt("pinned", "6969");
        Spi::run("SET pii_vault.mount_accessor = 'transit_somewhere_else'").unwrap();
        cache::flush();
        match keyring::open(&sealed(&value)) {
            Err(PiiError::Config(msg)) => {
                assert!(msg.contains("not the expected key space"), "{msg}")
            }
            other => panic!("expected a configuration error, got {:?}", other.err()),
        }
        Spi::run("SET pii_vault.mount_accessor = 'transit_fake0001'").unwrap();
        assert_eq!(decrypt(&value), "pinned");
    }

    #[pg_test]
    fn vault_fetch_racing_an_invalidation_is_not_cached() {
        let _fake = FakeVault::configured();
        let scope = config::endpoint().unwrap().scope();
        let keys = || {
            Some(std::sync::Arc::new(
                KeySet::new(vec![(1, Zeroizing::new([7u8; 32]))]).unwrap(),
            ))
        };
        // A shred of the same key while the answer was on its way.
        let since = crate::shared::generation();
        crate::shared::publish_key_change(&[0x70, 0x01]);
        assert!(!cache::put(&scope, &[0x70, 0x01], keys(), since));
        assert!(matches!(cache::get(&scope, &[0x70, 0x01]), Lookup::Miss));
        // A change of another key does not matter.
        let since = crate::shared::generation();
        crate::shared::publish_key_change(&[0x70, 0x02]);
        assert!(cache::put(&scope, &[0x70, 0x01], keys(), since));
        // piitext_cache_invalidate() during the fetch (simulated, so that the
        // caches of tests running in parallel are left alone).
        let mut since = crate::shared::generation();
        since.epoch = since.epoch.wrapping_sub(1);
        assert!(!cache::put(&scope, &[0x70, 0x03], keys(), since));
    }

    #[pg_test]
    fn vault_shred_invalidates_only_that_key() {
        let fake = FakeVault::configured();
        let kept = encrypt("other subject", "7101");
        let _gone = encrypt("erased subject", "7102");
        assert!(select_bool("SELECT piitext_shred('\\x7102'::bytea)"));
        let exports = fake.count("GET", "transit/export/encryption-key/7101");
        assert_eq!(decrypt(&kept), "other subject");
        assert_eq!(
            fake.count("GET", "transit/export/encryption-key/7101"),
            exports,
            "the other key stays cached"
        );
    }

    #[pg_test]
    fn vault_absent_keys_are_remembered_briefly() {
        let fake = FakeVault::configured();
        let value = encrypt("to be erased", "7201");
        assert!(select_bool("SELECT piitext_shred('\\x7201'::bytea)"));
        assert_eq!(decrypt(&value), "****");
        let exports = fake.count("GET", "transit/export/encryption-key/7201");
        for _ in 0..5 {
            assert_eq!(decrypt(&value), "****");
        }
        assert_eq!(
            fake.count("GET", "transit/export/encryption-key/7201"),
            exports,
            "reads of an erased subject do not hit Vault every time"
        );
        // Creating the key again (new data for the same key id) is announced,
        // so new values are not mistaken for erased ones.
        let fresh = encrypt("new data", "7201");
        assert_eq!(decrypt(&fresh), "new data");
        assert_eq!(decrypt(&value), "****");
    }

    #[pg_test]
    fn vault_cache_settings_apply_to_cached_keys() {
        let fake = FakeVault::configured();
        let value = encrypt("cached", "7301");
        let exports = || fake.count("GET", "transit/export/encryption-key/7301");
        let before = exports();
        assert_eq!(decrypt(&value), "cached");
        assert_eq!(exports(), before, "served from the cache");
        Spi::run("SET pii_vault.cache_ttl_sec = 0").unwrap();
        assert_eq!(decrypt(&value), "cached");
        assert_eq!(exports(), before + 1, "ttl 0 also ignores cached keys");
        assert_eq!(cache::len(), 0);
        Spi::run("SET pii_vault.cache_ttl_sec = 300").unwrap();
        assert_eq!(decrypt(&value), "cached");
        Spi::run("SET pii_vault.cache_max_entries = 0").unwrap();
        assert_eq!(decrypt(&value), "cached");
        assert_eq!(exports(), before + 3, "max 0 also ignores cached keys");
    }

    #[pg_test]
    fn vault_failed_shred_still_invalidates() {
        let fake = FakeVault::configured();
        let value = encrypt("cached everywhere", "7401");
        assert_eq!(decrypt(&value), "cached everywhere");
        let published = crate::shared::generation().key_seq;
        // The DELETE may have reached Vault although the answer is an error.
        fake.with(|s| {
            s.fail_on
                .push(("DELETE".into(), "transit/keys/7401".into(), 503))
        });
        assert!(matches!(
            keyring::shred(&[0x74, 0x01]),
            Err(PiiError::Unavailable(_))
        ));
        assert!(crate::shared::generation().key_seq > published);
        let scope = config::endpoint().unwrap().scope();
        assert!(matches!(cache::get(&scope, &[0x74, 0x01]), Lookup::Miss));
    }

    #[pg_test]
    fn vault_lost_delete_answer_counts_as_deleted() {
        let fake = FakeVault::configured();
        Spi::run("SET pii_vault.max_retries = 1").unwrap();
        let _value = encrypt("x", "7501");
        fake.with(|s| s.lose_delete_answer = true);
        assert!(select_bool("SELECT piitext_shred('\\x7501'::bytea)"));
        assert!(!fake.has_key("7501"));
        assert!(
            !select_bool("SELECT piitext_shred('\\x7501'::bytea)"),
            "a later call finds nothing to delete"
        );
    }

    #[pg_test]
    fn vault_reencrypt_uses_the_latest_version_despite_the_cache() {
        let fake = FakeVault::configured();
        let value = encrypt("rotate me", "7601");
        assert_eq!(decrypt(&value), "rotate me");
        // Rotated in Vault while this backend still caches version 1.
        fake.rotate("7601");
        std::thread::sleep(std::time::Duration::from_millis(2100));
        let upgraded = crate::piitext_reencrypt(value);
        assert_eq!(sealed(&upgraded).key_version, Some(2));
        assert_eq!(decrypt(&upgraded), "rotate me");
    }

    #[pg_test]
    fn vault_reencrypt_never_recreates_a_shredded_key() {
        let fake = FakeVault::configured();
        let value = encrypt("gone", "7701");
        assert_eq!(decrypt(&value), "gone");
        std::thread::sleep(std::time::Duration::from_millis(2100));
        // Shredded (by another cluster) between decryption and encryption.
        fake.remove_key("7701");
        match keyring::reseal("gone", &[0x77, 0x01]) {
            Err(PiiError::KeyNotFound(msg)) => assert!(msg.contains("crypto-shredded"), "{msg}"),
            other => panic!("expected KeyNotFound, got {:?}", other.err()),
        }
        assert!(!fake.has_key("7701"), "the key was not created again");
    }

    #[pg_test]
    fn vault_only_exact_transit_answers_count() {
        let fake = FakeVault::configured();
        let value = encrypt("guarded", "7801");
        cache::flush();
        for (status, body) in [
            (404, "{\"errors\":[],\"warnings\":[\"from a proxy\"]}"),
            (404, "{\"errors\":null}"),
            (404, "{}"),
        ] {
            fake.with(|s| s.raw_next.push_back((status, body.to_string())));
            assert!(
                keyring::open(&sealed(&value)).is_err(),
                "{status} {body} must be an error"
            );
        }
        for body in [
            "<html>no existing key named 7801 could be found</html>",
            "{\"errors\":[\"error deleting policy 7801: could not delete key; not found (proxy)\"]}",
        ] {
            fake.with(|s| {
                s.fail_on.clear();
                s.raw_next.push_back((400, body.to_string()));
            });
            assert!(
                keyring::shred(&[0x78, 0x01]).is_err(),
                "{body} is not Vault's answer for a missing key"
            );
        }
        assert!(fake.has_key("7801"));
        assert_eq!(decrypt(&value), "guarded");
    }

    #[pg_test]
    fn vault_error_text_has_no_control_characters() {
        let fake = FakeVault::configured();
        let value = encrypt("x", "7901");
        cache::flush();
        fake.with(|s| {
            s.raw_next
                .push_back((500, "{\"errors\":[\"bad\\u001b[31m thing\\nhere\"]}".into()))
        });
        match keyring::open(&sealed(&value)) {
            Err(PiiError::Unavailable(msg)) => {
                assert!(!msg.chars().any(char::is_control), "{msg:?}");
                assert!(msg.contains("bad [31m thing here"), "{msg:?}");
            }
            other => panic!("expected Unavailable, got {:?}", other.err()),
        }
    }
}

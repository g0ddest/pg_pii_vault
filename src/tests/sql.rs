#[pgrx::pg_schema]
mod tests {
    use crate::config;
    use crate::tests::{encrypt, select_bool, select_text};
    use pgrx::prelude::*;

    #[pg_test(error = "functions in index expression must be marked IMMUTABLE")]
    fn sql_decrypted_value_cannot_be_indexed() {
        Spi::run("CREATE TABLE idx_t (s piitext)").unwrap();
        Spi::run("CREATE INDEX ON idx_t ((s::text))").unwrap();
    }

    #[pg_test(error = "generation expression is not immutable")]
    fn sql_decrypted_value_cannot_be_a_stored_generated_column() {
        Spi::run("CREATE TABLE gen_t (s piitext, p text GENERATED ALWAYS AS (s::text) STORED)")
            .unwrap();
    }

    #[pg_test]
    fn sql_function_markings() {
        let marking = |sig: &str| {
            select_text(&format!(
                "SELECT provolatile::text || proparallel::text || CASE WHEN proisstrict THEN 's' ELSE 'n' END \
                 FROM pg_proc WHERE oid = '{sig}'::regprocedure"
            ))
        };
        // volatility, parallel safety, strictness
        assert_eq!(marking("piitext_out_text(piitext)"), "sss");
        assert_eq!(marking("piitext_in_text(text)"), "sss");
        assert_eq!(marking("piitext_encrypt(text, bytea)"), "vun");
        assert_eq!(marking("piitext_encrypt_piitext(piitext, bytea)"), "vun");
        assert_eq!(marking("piitext_reencrypt(piitext)"), "vus");
        assert_eq!(marking("piitext_debug(piitext)"), "iss");
        assert_eq!(marking("piitext_key_id(piitext)"), "iss");
        // The input functions depend on pii_vault.allow_staging.
        assert_eq!(marking("piitext_in(cstring)"), "ssn");
        assert_eq!(marking("piitext_recv(internal)"), "sss");
        assert_eq!(marking("piitext_out(piitext)"), "iss");
        assert_eq!(marking("piitext_send(piitext)"), "iss");
        let cost = Spi::get_one::<f32>(
            "SELECT procost FROM pg_proc WHERE oid = 'piitext_out_text(piitext)'::regprocedure",
        )
        .unwrap()
        .unwrap();
        assert_eq!(cost, 100.0);
    }

    #[pg_test(error = "column \"s\" is of type piitext but expression is of type text")]
    fn sql_text_is_never_stored_as_plaintext_implicitly() {
        Spi::run("CREATE TABLE w_t (s piitext)").unwrap();
        Spi::run("INSERT INTO w_t VALUES ('secret'::text)").unwrap();
    }

    #[pg_test(error = "column \"p\" is of type text but expression is of type piitext")]
    fn sql_no_implicit_decryption_into_text_columns() {
        Spi::run("CREATE TABLE r_t (p text)").unwrap();
        Spi::run("INSERT INTO r_t (p) SELECT piitext_encrypt('x', '\\x01'::bytea)").unwrap();
    }

    #[pg_test(error = "operator does not exist: piitext = unknown")]
    fn sql_no_hidden_decryption_in_where_clauses() {
        Spi::run("CREATE TABLE q_t (s piitext)").unwrap();
        Spi::run("SELECT * FROM q_t WHERE s = 'x'").unwrap();
    }

    #[pg_test]
    fn sql_explicit_casts_decrypt() {
        assert_eq!(
            select_text("SELECT piitext_encrypt('explicit', '\\x01'::bytea)::text"),
            "explicit"
        );
        assert_eq!(
            select_text("SELECT CAST(piitext_encrypt('explicit', '\\x01'::bytea) AS varchar)"),
            "explicit"
        );
        // A piitext value round-trips through its text form in a column.
        Spi::run("CREATE TABLE rt_t (id int, s piitext)").unwrap();
        Spi::run("INSERT INTO rt_t SELECT 1, piitext_encrypt('stored', '\\x0102'::bytea)").unwrap();
        let text = select_text("SELECT format('%s', s) FROM rt_t");
        Spi::run(&format!("INSERT INTO rt_t VALUES (2, '{text}')")).unwrap();
        assert_eq!(
            select_text("SELECT s::text FROM rt_t WHERE id = 2"),
            "stored"
        );
    }

    #[pg_test]
    fn sql_null_handling() {
        assert!(select_bool(
            "SELECT piitext_encrypt(NULL, '\\x01'::bytea) IS NULL"
        ));
        assert!(select_bool("SELECT piitext_encrypt(NULL, NULL) IS NULL"));
        assert!(select_bool("SELECT piitext_out_text(NULL) IS NULL"));
        assert!(select_bool(
            "SELECT piitext_encrypt_piitext(NULL, '\\x01'::bytea) IS NULL"
        ));
        assert!(select_bool("SELECT piitext_key_id(NULL) IS NULL"));
    }

    #[pg_test(error = "key id must not be NULL")]
    fn sql_null_key_id_is_an_error() {
        // STRICT would have silently turned the value into NULL.
        Spi::run("SELECT piitext_encrypt('data', NULL)").unwrap();
    }

    #[pg_test(error = "key id must not be NULL")]
    fn sql_null_key_id_is_an_error_on_reencryption() {
        Spi::run("SELECT piitext_encrypt_piitext(piitext_in_text('data'), NULL)").unwrap();
    }

    #[pg_test(error = "key id must not be empty")]
    fn sql_empty_key_id_is_rejected() {
        Spi::run("SELECT piitext_encrypt('data', ''::bytea)").unwrap();
    }

    #[pg_test(error = "key id is 129 bytes long; the maximum is 128")]
    fn sql_overlong_key_id_is_rejected() {
        Spi::run("SELECT piitext_encrypt('data', decode(repeat('ab', 129), 'hex'))").unwrap();
    }

    #[pg_test(error = "value is 16777217 bytes long; piitext values are limited to 16777216 bytes")]
    fn sql_value_size_is_limited() {
        Spi::run("SELECT piitext_encrypt(repeat('a', 16777217), '\\x01'::bytea)").unwrap();
    }

    #[pg_test(error = "plaintext piitext values are disabled (pii_vault.allow_staging = off)")]
    fn sql_staging_can_be_disabled() {
        Spi::run("SET pii_vault.allow_staging = off").unwrap();
        Spi::run("SELECT piitext_in_text('plain')").unwrap();
    }

    #[pg_test(error = "plaintext piitext values are disabled (pii_vault.allow_staging = off)")]
    fn sql_staging_literals_are_refused_when_disabled() {
        // The type's input function is a way in for plaintext, too.
        let sealed = select_text("SELECT format('%s', piitext_encrypt('ok', '\\x01'::bytea))");
        let staging = select_text("SELECT format('%s', piitext_in_text('plain'))");
        Spi::run("SET pii_vault.allow_staging = off").unwrap();
        assert_eq!(
            select_text(&format!("SELECT '{sealed}'::piitext::text")),
            "ok",
            "encrypted values are still accepted"
        );
        Spi::run(&format!("SELECT '{staging}'::piitext")).unwrap();
    }

    #[pg_test(error = "value is 16777217 bytes long; piitext values are limited to 16777216 bytes")]
    fn sql_staging_literal_size_is_limited() {
        Spi::run(
            "SELECT ('piitext:' || translate(encode(convert_to(repeat('a', 16777217), 'UTF8'), 'base64'), E'\n', ''))::piitext",
        )
        .unwrap();
    }

    fn binary_copy_file(tag: &str) -> String {
        std::env::temp_dir()
            .join(format!(
                "pg_pii_vault_copy_{tag}_{}.bin",
                std::process::id()
            ))
            .display()
            .to_string()
    }

    #[pg_test]
    fn sql_binary_copy_roundtrips() {
        let file = binary_copy_file("roundtrip");
        Spi::run("CREATE TABLE bin_src (id int, s piitext)").unwrap();
        Spi::run(
            "INSERT INTO bin_src VALUES (1, piitext_encrypt('sealed value', int4send(1))), \
             (2, piitext_in_text('staging value')), (3, NULL)",
        )
        .unwrap();
        Spi::run(&format!("COPY bin_src TO '{file}' WITH (FORMAT binary)")).unwrap();
        Spi::run("CREATE TABLE bin_dst (id int, s piitext)").unwrap();
        Spi::run(&format!("COPY bin_dst FROM '{file}' WITH (FORMAT binary)")).unwrap();
        std::fs::remove_file(&file).unwrap();
        assert_eq!(
            select_text(
                "SELECT string_agg(id || '=' || coalesce(s::text, 'NULL'), ',' ORDER BY id) FROM bin_dst"
            ),
            "1=sealed value,2=staging value,3=NULL"
        );
        assert!(select_bool(
            "SELECT bool_and(piitext_raw(a.s) IS NOT DISTINCT FROM piitext_raw(b.s)) \
             FROM bin_src a JOIN bin_dst b USING (id)"
        ));
    }

    #[pg_test(error = "plaintext piitext values are disabled (pii_vault.allow_staging = off)")]
    fn sql_binary_copy_refuses_staging_values_when_disabled() {
        let file = binary_copy_file("staging");
        Spi::run("CREATE TABLE bin_stg (s piitext)").unwrap();
        Spi::run("INSERT INTO bin_stg VALUES (piitext_in_text('plain'))").unwrap();
        Spi::run(&format!("COPY bin_stg TO '{file}' WITH (FORMAT binary)")).unwrap();
        Spi::run("SET pii_vault.allow_staging = off").unwrap();
        let outcome = std::panic::catch_unwind(|| {
            Spi::run(&format!("COPY bin_stg FROM '{file}' WITH (FORMAT binary)")).unwrap();
        });
        let _ = std::fs::remove_file(&file);
        if let Err(e) = outcome {
            std::panic::resume_unwind(e);
        }
    }

    #[pg_test]
    fn sql_staging_values_are_encrypted_in_place() {
        Spi::run("CREATE TABLE m_t (id int, s piitext)").unwrap();
        Spi::run("INSERT INTO m_t VALUES (1, piitext_in_text('migrating'))").unwrap();
        assert!(!select_bool("SELECT piitext_is_encrypted(s) FROM m_t"));
        Spi::run("UPDATE m_t SET s = piitext_encrypt_piitext(s, int4send(id))").unwrap();
        assert!(select_bool("SELECT piitext_is_encrypted(s) FROM m_t"));
        assert_eq!(select_text("SELECT s::text FROM m_t"), "migrating");
        assert_eq!(
            select_text("SELECT encode(piitext_key_id(s), 'hex') FROM m_t"),
            "00000001"
        );
    }

    #[pg_test]
    fn sql_metadata_accessors() {
        assert!(!select_bool(
            "SELECT piitext_is_encrypted(piitext_in_text('hello'))"
        ));
        assert!(select_bool(
            "SELECT piitext_key_id(piitext_in_text('hello')) IS NULL"
        ));
        assert!(select_bool(
            "SELECT piitext_key_version(piitext_in_text('hello')) IS NULL"
        ));
        assert_eq!(
            select_text("SELECT piitext_debug(piitext_in_text('hello'))"),
            "Staging(plaintext_bytes=5)"
        );

        let sealed = "piitext_encrypt('top secret', '\\x0a0b'::bytea)";
        assert!(select_bool(&format!(
            "SELECT piitext_is_encrypted({sealed})"
        )));
        assert_eq!(
            select_text(&format!("SELECT encode(piitext_key_id({sealed}), 'hex')")),
            "0a0b"
        );
        assert_eq!(
            Spi::get_one::<i64>(&format!("SELECT piitext_key_version({sealed})"))
                .unwrap()
                .unwrap(),
            1
        );
        let debug = select_text(&format!("SELECT piitext_debug({sealed})"));
        assert_eq!(
            debug,
            "Sealed(format=2, key_id=\\x0a0b, key_version=1, ciphertext_bytes=10)"
        );
        assert!(!debug.contains("top secret"));
    }

    #[pg_test]
    fn sql_privileges_are_least_privilege_by_default() {
        Spi::run("CREATE ROLE pii_probe_role").unwrap();
        let can = |sig: &str| {
            select_bool(&format!(
                "SELECT has_function_privilege('pii_probe_role', '{sig}', 'EXECUTE')"
            ))
        };
        for restricted in [
            "piitext_out_text(piitext)",
            "piitext_encrypt(text, bytea)",
            "piitext_encrypt_piitext(piitext, bytea)",
            "piitext_reencrypt(piitext)",
            "piitext_shred(bytea)",
            "piitext_cache_invalidate()",
            "piitext_vault_check()",
        ] {
            assert!(
                !can(restricted),
                "{restricted} must not be executable by PUBLIC"
            );
        }
        for public in [
            "piitext_in(cstring)",
            "piitext_out(piitext)",
            "piitext_send(piitext)",
            "piitext_is_encrypted(piitext)",
            "piitext_key_id(piitext)",
            "piitext_in_text(text)",
            "piitext_stats()",
            "piitext_cache_flush()",
        ] {
            assert!(can(public), "{public} should be executable by PUBLIC");
        }
    }

    fn reader_setup() {
        Spi::run("CREATE ROLE pii_reader_probe").unwrap();
        Spi::run("CREATE TABLE p_t (s piitext)").unwrap();
        Spi::run("INSERT INTO p_t SELECT piitext_encrypt('classified', '\\x01'::bytea)").unwrap();
        Spi::run("GRANT SELECT ON p_t TO pii_reader_probe").unwrap();
    }

    #[pg_test(error = "permission denied for function piitext_out_text")]
    fn sql_decryption_requires_an_explicit_grant() {
        reader_setup();
        Spi::run("SET ROLE pii_reader_probe").unwrap();
        Spi::run("SELECT s::text FROM p_t").unwrap();
    }

    #[pg_test]
    fn sql_select_privilege_alone_yields_ciphertext() {
        reader_setup();
        Spi::run("SET ROLE pii_reader_probe").unwrap();
        let visible = select_text("SELECT format('%s', s) FROM p_t");
        Spi::run("RESET ROLE").unwrap();
        assert!(visible.starts_with("piitext:"));
        assert!(!visible.contains("classified"));
        Spi::run("GRANT EXECUTE ON FUNCTION piitext_out_text(piitext) TO pii_reader_probe")
            .unwrap();
        Spi::run("SET ROLE pii_reader_probe").unwrap();
        let plain = select_text("SELECT s::text FROM p_t");
        Spi::run("RESET ROLE").unwrap();
        assert_eq!(plain, "classified");
    }

    #[pg_test(error = "permission denied to set parameter \"pii_vault.url\"")]
    fn sql_vault_url_is_superuser_only() {
        Spi::run("CREATE ROLE pii_url_probe").unwrap();
        Spi::run("SET ROLE pii_url_probe").unwrap();
        Spi::run("SET pii_vault.url = 'https://attacker.example'").unwrap();
    }

    #[pg_test(error = "permission denied to set parameter \"pii_vault.token\"")]
    fn sql_vault_token_is_superuser_only() {
        Spi::run("CREATE ROLE pii_token_probe").unwrap();
        Spi::run("SET ROLE pii_token_probe").unwrap();
        Spi::run("SET pii_vault.token = 'x'").unwrap();
    }

    #[pg_test]
    fn sql_vault_token_is_hidden_from_other_roles() {
        Spi::run("SET pii_vault.token = 'hidden-token'").unwrap();
        Spi::run("CREATE ROLE pii_show_probe").unwrap();
        let visible = |role: Option<&str>| {
            if let Some(r) = role {
                Spi::run(&format!("SET ROLE {r}")).unwrap();
            }
            let n = Spi::get_one::<i64>(
                "SELECT count(*) FROM pg_settings WHERE name = 'pii_vault.token'",
            )
            .unwrap()
            .unwrap();
            Spi::run("RESET ROLE").unwrap();
            n
        };
        assert_eq!(visible(None), 1, "superuser sees the parameter");
        assert_eq!(visible(Some("pii_show_probe")), 0, "other roles do not");
    }

    #[pg_test(error = "invalid value for parameter \"pii_vault.url\": \"vault.example:8200\"")]
    fn sql_vault_url_is_validated_on_set() {
        Spi::run("SET pii_vault.url = 'vault.example:8200'").unwrap();
    }

    // The pii_vault prefix is reserved with MarkGUCPrefixReserved (PostgreSQL 15+);
    // PostgreSQL 14 only warns about unknown names.
    #[cfg(not(feature = "pg14"))]
    #[pg_test(error = "invalid configuration parameter name \"pii_vault.tokn\"")]
    fn sql_parameter_typos_are_rejected() {
        Spi::run("SET pii_vault.tokn = 'x'").unwrap();
    }

    #[pg_test]
    fn sql_url_rules() {
        use config::validate_url;
        assert!(validate_url("https://vault.example.com:8200").is_ok());
        assert!(validate_url("http://127.0.0.1:8200/").is_ok());
        assert!(validate_url("https://proxy.example.com/vault").is_ok());
        assert!(validate_url("").is_ok(), "unset");
        assert!(validate_url("vault.example.com:8200").is_err());
        assert!(validate_url("ftp://vault").is_err());
        assert!(validate_url("https://").is_err());
        assert!(validate_url("https://vault/?x=1").is_err());
        assert!(validate_url("https://va ult").is_err());
        assert!(
            validate_url("https://user:secret@vault.example:8200").is_err(),
            "no credentials in the URL"
        );
        assert!(validate_url("https://vault.example:8200/proxy/a@b").is_ok());

        let endpoint_for = |url: &str| {
            Spi::run(&format!("SET pii_vault.url = '{url}'")).unwrap();
            config::endpoint()
        };
        assert!(
            endpoint_for("http://127.0.0.1:8200").is_ok(),
            "loopback http is fine"
        );
        assert!(endpoint_for("http://localhost:8200").is_ok());
        assert!(endpoint_for("http://[::1]:8200").is_ok());
        assert!(endpoint_for("https://vault.example:8200").is_ok());
        assert!(
            endpoint_for("http://vault.example:8200").is_err(),
            "plain http elsewhere"
        );
        Spi::run("SET pii_vault.allow_insecure_http = on").unwrap();
        assert!(endpoint_for("http://vault.example:8200").is_ok());
        let ep = endpoint_for("https://vault.example:8200///").unwrap();
        assert_eq!(ep.base_url, "https://vault.example:8200");
        assert_eq!(ep.mount, "transit");

        for bad_mount in ["../sys", "a//b", "a/./b", "sp ace", "x?y"] {
            Spi::run(&format!("SET pii_vault.mount = '{bad_mount}'")).unwrap();
            assert!(
                config::endpoint().is_err(),
                "mount {bad_mount:?} must be rejected"
            );
        }
        Spi::run("SET pii_vault.mount = '/team-a/transit/'").unwrap();
        assert_eq!(config::endpoint().unwrap().mount, "team-a/transit");
    }

    #[pg_test]
    fn sql_stats_and_shared_memory() {
        assert!(
            crate::shared::available(),
            "tests run with the library preloaded"
        );
        let _ = encrypt("counted", "01");
        let metrics = Spi::get_one::<i64>("SELECT count(*) FROM piitext_stats()")
            .unwrap()
            .unwrap();
        assert_eq!(metrics, 10);
        assert!(select_bool(
            "SELECT count(*) = 1 FROM piitext_stats() WHERE metric = 'vault_denied'"
        ));
        assert!(select_bool(
            "SELECT cluster IS NOT NULL FROM piitext_stats() WHERE metric = 'vault_requests'"
        ));
        assert!(select_bool("SELECT piitext_cache_invalidate()"));
    }
}

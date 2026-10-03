#[pgrx::pg_schema]
mod tests {
    use crate::contents::{self, PiiSealedData, PiiTextContents, FORMAT_V1, FORMAT_V2};
    use crate::error::PiiError;
    use crate::tests::{decrypt, encrypt, sealed, select_text};
    use crate::PiiText;
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use pgrx::datum::FromDatum;
    use pgrx::prelude::*;
    use serde::Serialize;

    /// Sealed layout written by pg_pii_vault 0.0.x: byte fields as CBOR arrays.
    #[derive(Serialize)]
    struct LegacySealed {
        #[serde(rename = "v")]
        version: u8,
        #[serde(rename = "k")]
        key_id: Vec<u8>,
        #[serde(rename = "i")]
        iv: Vec<u8>,
        #[serde(rename = "t")]
        tag: Vec<u8>,
        #[serde(rename = "c")]
        ciphertext: Vec<u8>,
    }

    /// pgrx's default datum / JSON wrapper used by 0.0.x.
    #[derive(Serialize)]
    struct LegacyWrapper {
        inner: Vec<u8>,
    }

    fn mock_key(key_id: &[u8]) -> [u8; 32] {
        *crate::keyring::mock_keyset(key_id).latest().1
    }

    /// Bytes of a value encrypted exactly the way 0.0.x did it.
    fn legacy_sealed(plaintext: &str, key_id: &[u8]) -> Vec<u8> {
        let key = mock_key(key_id);
        let iv = [7u8; 12];
        let aad = format!("col:piitext:id:{}", hex::encode(key_id));
        let out = Aes256Gcm::new(&key.into())
            .encrypt(
                Nonce::from_slice(&iv),
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: aad.as_bytes(),
                },
            )
            .unwrap();
        let (ciphertext, tag) = out.split_at(out.len() - 16);
        serde_cbor::to_vec(&LegacySealed {
            version: 1,
            key_id: key_id.to_vec(),
            iv: iv.to_vec(),
            tag: tag.to_vec(),
            ciphertext: ciphertext.to_vec(),
        })
        .unwrap()
    }

    #[pg_test]
    fn format_legacy_json_text_value_decrypts() {
        let inner = legacy_sealed("legacy secret", &[0, 0, 0, 1]);
        let json = serde_json::to_string(&LegacyWrapper { inner }).unwrap();
        assert!(json.starts_with("{\"inner\":["));
        assert_eq!(
            select_text(&format!("SELECT piitext_out_text('{json}'::piitext)")),
            "legacy secret"
        );
        let version =
            Spi::get_one::<i64>(&format!("SELECT piitext_key_version('{json}'::piitext)")).unwrap();
        assert_eq!(version, None, "0.0.x values do not record the key version");
        assert!(
            select_text(&format!("SELECT piitext_debug('{json}'::piitext)")).contains("format=1")
        );
    }

    #[pg_test]
    fn format_legacy_storage_wrapper_is_read() {
        let inner = legacy_sealed("wrapped", &[9]);
        let wrapper = serde_cbor::to_vec(&LegacyWrapper {
            inner: inner.clone(),
        })
        .unwrap();
        assert_eq!(&wrapper[..7], &[0xA1, 0x65, b'i', b'n', b'n', b'e', b'r']);
        let datum = pgrx::varlena::rust_byte_slice_to_bytea(&wrapper).into_pg();
        let value = unsafe { <PiiText as FromDatum>::from_datum(datum.into(), false) }.unwrap();
        assert_eq!(value.inner, inner, "the 0.0.x wrapper is stripped on read");
        assert_eq!(decrypt(&value), "wrapped");

        // Staging values were wrapped too.
        let staging = serde_cbor::to_vec(&LegacyWrapper {
            inner: b"old plaintext".to_vec(),
        })
        .unwrap();
        let datum = pgrx::varlena::rust_byte_slice_to_bytea(&staging).into_pg();
        let value = unsafe { <PiiText as FromDatum>::from_datum(datum.into(), false) }.unwrap();
        assert_eq!(decrypt(&value), "old plaintext");
    }

    #[pg_test]
    fn format_new_values_use_format_2_with_key_version() {
        let value = encrypt("hello", "0000007b");
        let s = sealed(&value);
        assert_eq!(s.version, FORMAT_V2);
        assert_eq!(s.key_version, Some(1));
        assert_eq!(s.key_id, vec![0, 0, 0, 123]);
        assert_eq!(s.iv.len(), 12);
        assert_eq!(s.tag.len(), 16);
        assert_eq!(s.ciphertext.len(), 5);
        assert_eq!(value.inner[0] & 0xE0, 0xA0, "stored as a CBOR map");
        assert_eq!(decrypt(&value), "hello");
    }

    #[pg_test]
    fn format_same_plaintext_encrypts_differently() {
        let a = encrypt("same", "01");
        let b = encrypt("same", "01");
        assert_ne!(sealed(&a).iv, sealed(&b).iv, "every value gets a fresh IV");
        assert_ne!(a.inner, b.inner);
    }

    #[pg_test]
    fn format_text_representation_roundtrips() {
        let text =
            select_text("SELECT format('%s', piitext_encrypt('round trip', '\\x01'::bytea))");
        assert!(text.starts_with("piitext:"), "got {text}");
        assert_eq!(
            select_text(&format!("SELECT piitext_out_text('{text}'::piitext)")),
            "round trip"
        );
        let staging = select_text("SELECT format('%s', piitext_in_text('plain'))");
        assert_eq!(staging, format!("piitext:{}", STANDARD.encode("plain")));
        assert_eq!(
            select_text(&format!("SELECT piitext_out_text('{staging}'::piitext)")),
            "plain"
        );
    }

    #[pg_test(
        error = "invalid input syntax for type piitext: expected a value starting with \"piitext:\""
    )]
    fn format_plain_literal_is_rejected() {
        Spi::run("SELECT 'my secret'::piitext").unwrap();
    }

    #[pg_test]
    fn format_malformed_values_are_rejected() {
        let bad_inputs = [
            "piitext:!!!not-base64",
            "{\"inner\": \"not bytes\"}",
            "{not json",
            "PIITEXT:AAAA",
        ];
        for input in bad_inputs {
            assert!(
                matches!(contents::decode_text(input), Err(PiiError::InvalidText(_))),
                "{input} must be rejected"
            );
        }

        let mut good = PiiSealedData {
            version: FORMAT_V2,
            key_id: vec![1],
            key_version: Some(1),
            iv: vec![0; 12],
            tag: vec![0; 16],
            ciphertext: vec![1, 2, 3],
        };
        let parses =
            |s: &PiiSealedData| PiiTextContents::parse(&serde_cbor::to_vec(s).unwrap()).is_ok();
        assert!(parses(&good));
        good.iv = vec![0; 11];
        assert!(!parses(&good), "short IV");
        good.iv = vec![0; 12];
        good.tag = vec![0; 15];
        assert!(!parses(&good), "short tag");
        good.tag = vec![0; 16];
        good.key_id = vec![];
        assert!(!parses(&good), "empty key id");
        good.key_id = vec![1];
        good.key_version = None;
        assert!(!parses(&good), "format 2 without key version");
        good.version = FORMAT_V1;
        assert!(parses(&good), "format 1 has no key version");
        good.key_version = Some(3);
        assert!(!parses(&good), "format 1 must not carry a key version");
        good.version = 9;
        assert!(!parses(&good), "unknown format version");

        assert!(
            PiiTextContents::parse(&[0xA5, 0x00]).is_err(),
            "truncated CBOR"
        );
        assert!(
            PiiTextContents::parse(&[0xC3, 0x28]).is_err(),
            "invalid UTF-8 staging"
        );
    }

    #[pg_test]
    fn format_utf8_text_is_never_mistaken_for_sealed() {
        // A CBOR map starts with 0xA0..=0xBF, a UTF-8 continuation byte, so no
        // text can look sealed - even text crafted to be valid CBOR (0xC5 is
        // a CBOR tag, 0x85 an array header).
        let crafted = "\u{0145}\u{0001}Ax";
        for text in [
            "",
            "a",
            "Žlutý kůň",
            crafted,
            "{\"inner\":[1]}",
            "piitext:AAAA",
            "😀",
        ] {
            let value = crate::piitext_input(text);
            assert!(
                matches!(value.contents(), PiiTextContents::Staging(_)),
                "{text:?} must stay staging"
            );
            assert_eq!(decrypt(&value), text);
        }
    }

    #[pg_test]
    fn format_binary_output_is_the_value_bytes() {
        let bytes =
            Spi::get_one::<Vec<u8>>("SELECT piitext_send(piitext_encrypt('b', '\\x02'::bytea))")
                .unwrap()
                .unwrap();
        assert_eq!(bytes[0] & 0xE0, 0xA0);
        assert!(PiiTextContents::parse(&bytes).is_ok());
        let staging = Spi::get_one::<Vec<u8>>("SELECT piitext_send(piitext_in_text('plain'))")
            .unwrap()
            .unwrap();
        assert_eq!(staging, b"plain");
    }

    #[pg_test]
    fn format_storage_is_compact() {
        // 5 bytes of plaintext: 0.0.x needed 171 bytes on disk.
        let size =
            Spi::get_one::<i32>("SELECT pg_column_size(piitext_encrypt('hello', '\\x01'::bytea))")
                .unwrap()
                .unwrap();
        assert!(size < 70, "stored size {size}");
    }

    #[pg_test]
    fn format_sealed_values_are_strictly_validated() {
        use crate::contents::{FORMAT_V3, MAX_LEGACY_KEY_ID_LEN};
        let parses =
            |s: &PiiSealedData| PiiTextContents::parse(&serde_cbor::to_vec(s).unwrap()).is_ok();
        let base = PiiSealedData {
            version: FORMAT_V2,
            key_id: vec![1],
            key_version: Some(1),
            iv: vec![0; 12],
            tag: vec![0; 16],
            ciphertext: vec![1, 2, 3],
        };

        let mut v = base.clone();
        v.key_id = vec![1; 128];
        assert!(parses(&v));
        v.key_id = vec![1; 129];
        assert!(!parses(&v), "format 2 key ids have at most 128 bytes");
        v.version = FORMAT_V1;
        v.key_version = None;
        assert!(parses(&v), "0.0.x allowed longer key ids");
        v.key_id = vec![1; MAX_LEGACY_KEY_ID_LEN + 1];
        assert!(!parses(&v));

        let mut v = base.clone();
        v.ciphertext = vec![0; crate::MAX_PLAINTEXT_BYTES + 1];
        assert!(!parses(&v), "ciphertext larger than any value");

        let transit = |c: &str, kv: u32| PiiSealedData {
            version: FORMAT_V3,
            key_id: vec![1],
            key_version: Some(kv),
            iv: vec![],
            tag: vec![],
            ciphertext: c.as_bytes().to_vec(),
        };
        assert!(parses(&transit("vault:v2:QUJD", 2)));
        assert!(!parses(&transit("vault:v1:QUJD", 2)), "version must match");
        assert!(!parses(&transit("vault:v0:QUJD", 1)), "no version 0");
        assert!(!parses(&transit("vault:v01:QUJD", 1)), "no leading zero");
        assert!(!parses(&transit("vault:v1:QU\"D", 1)), "base64 only");
        assert!(!parses(&transit("vault:v1:QUJ", 1)), "padded base64 only");
        assert!(!parses(&transit("vault:v1:", 1)));

        #[derive(Serialize)]
        struct WithExtraField {
            v: u8,
            #[serde(with = "serde_bytes")]
            k: Vec<u8>,
            kv: u32,
            #[serde(with = "serde_bytes")]
            i: Vec<u8>,
            #[serde(with = "serde_bytes")]
            t: Vec<u8>,
            #[serde(with = "serde_bytes")]
            c: Vec<u8>,
            x: String,
        }
        let smuggled = serde_cbor::to_vec(&WithExtraField {
            v: 2,
            k: vec![1],
            kv: 1,
            i: vec![0; 12],
            t: vec![0; 16],
            c: vec![1],
            x: "hidden plaintext".into(),
        })
        .unwrap();
        assert!(PiiTextContents::parse(&smuggled).is_err(), "unknown fields");
    }

    #[pg_test]
    fn format_input_must_use_the_canonical_encoding() {
        // A format 2 value with its byte fields as CBOR arrays, as 0.0.x
        // wrote them: readable, but not what 0.1.0 writes.
        #[derive(Serialize)]
        struct ArrayFields {
            v: u8,
            k: Vec<u8>,
            kv: u32,
            i: Vec<u8>,
            t: Vec<u8>,
            c: Vec<u8>,
        }
        let bytes = serde_cbor::to_vec(&ArrayFields {
            v: 2,
            k: vec![1],
            kv: 1,
            i: vec![0; 12],
            t: vec![0; 16],
            c: vec![1, 2],
        })
        .unwrap();
        assert!(PiiTextContents::parse(&bytes).is_ok());
        assert!(matches!(
            PiiTextContents::parse_input(&bytes),
            Err(PiiError::Corrupted(_))
        ));
        assert!(
            PiiTextContents::parse_input(&legacy_sealed("old", &[1])).is_ok(),
            "values written by 0.0.x keep their layout"
        );
        let own = encrypt("canonical", "01");
        assert!(PiiTextContents::parse_input(&own.inner).is_ok());

        // Oversized input is refused before it is decoded.
        let huge = format!("piitext:{}", "A".repeat(30 * 1024 * 1024));
        assert!(matches!(
            contents::decode_text(&huge),
            Err(PiiError::InvalidArgument(_))
        ));
    }
}

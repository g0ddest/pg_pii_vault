//! In-database tests (`cargo pgrx test`). They run inside a PostgreSQL
//! backend of a throw-away cluster started with `shared_preload_libraries =
//! 'pg_pii_vault'`. Vault behaviour is exercised against `fake_vault`; set
//! PII_VAULT_TEST_URL / PII_VAULT_TEST_TOKEN to also run `real_vault` against
//! a real Vault dev server with the Transit engine mounted at `transit/`.

pub mod fake_vault;
mod format;
mod real_vault;
mod sql;
mod transit;
mod vault;

use crate::contents::{PiiSealedData, PiiTextContents};
use crate::PiiText;
use pgrx::prelude::*;

pub fn select_piitext(query: &str) -> PiiText {
    Spi::get_one::<PiiText>(query)
        .expect("query failed")
        .expect("query returned NULL")
}

pub fn select_text(query: &str) -> String {
    Spi::get_one::<String>(query)
        .expect("query failed")
        .expect("query returned NULL")
}

pub fn select_bool(query: &str) -> bool {
    Spi::get_one::<bool>(query)
        .expect("query failed")
        .expect("query returned NULL")
}

pub fn encrypt(plaintext: &str, key_hex: &str) -> PiiText {
    select_piitext(&format!(
        "SELECT piitext_encrypt('{plaintext}', '\\x{key_hex}'::bytea)"
    ))
}

pub fn decrypt(value: &PiiText) -> String {
    crate::piitext_output(value.clone())
}

pub fn sealed(value: &PiiText) -> PiiSealedData {
    match value.contents() {
        PiiTextContents::Sealed(s) => s,
        PiiTextContents::Staging(_) => panic!("expected a sealed value"),
    }
}

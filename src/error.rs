use crate::shared::{self, Counter};
use pgrx::pg_sys::panic::ErrorReport;
use pgrx::{PgLogLevel, PgSqlErrorCode};
use std::fmt;

/// Every failure the extension can raise, mapped to a stable SQLSTATE so that
/// applications can tell "Vault is down, retry" apart from "your data is bad".
#[derive(Debug)]
pub enum PiiError {
    /// The extension is not configured or misconfigured (missing URL/token,
    /// unreadable files, wrong mount).
    Config(String),
    /// The caller passed an unusable argument (bad key id, wrong value kind).
    InvalidArgument(String),
    /// A text literal is not a valid piitext external representation.
    InvalidText(String),
    /// A stored value cannot be decoded.
    Corrupted(String),
    /// Vault answered 401/403: the token is invalid, expired or revoked, or
    /// its policy does not allow the operation.
    PermissionDenied(String),
    /// Vault is unreachable, timed out, sealed, or kept failing after retries.
    Unavailable(String),
    /// Vault returned an unexpected status or payload.
    Vault(String),
    /// The key (or the key version) does not exist in Vault.
    KeyNotFound(String),
    /// Plaintext staging values are disabled by `pii_vault.allow_staging`.
    StagingDisabled,
}

impl PiiError {
    fn sqlstate(&self) -> PgSqlErrorCode {
        match self {
            PiiError::Config(_) | PiiError::StagingDisabled => {
                PgSqlErrorCode::ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE
            }
            PiiError::InvalidArgument(_) => PgSqlErrorCode::ERRCODE_INVALID_PARAMETER_VALUE,
            PiiError::InvalidText(_) => PgSqlErrorCode::ERRCODE_INVALID_TEXT_REPRESENTATION,
            PiiError::Corrupted(_) => PgSqlErrorCode::ERRCODE_DATA_CORRUPTED,
            PiiError::PermissionDenied(_) => PgSqlErrorCode::ERRCODE_INSUFFICIENT_PRIVILEGE,
            PiiError::Unavailable(_) => PgSqlErrorCode::ERRCODE_SYSTEM_ERROR,
            PiiError::Vault(_) => PgSqlErrorCode::ERRCODE_EXTERNAL_ROUTINE_EXCEPTION,
            PiiError::KeyNotFound(_) => PgSqlErrorCode::ERRCODE_UNDEFINED_OBJECT,
        }
    }

    fn hint(&self) -> Option<&'static str> {
        match self {
            PiiError::Config(_) => Some(
                "Check the pii_vault.* settings (superuser only); SELECT * FROM piitext_vault_check() shows what is wrong.",
            ),
            PiiError::PermissionDenied(_) => Some(
                "Check that the Vault token is valid (not expired or revoked) and that its policy allows the request; SELECT * FROM piitext_vault_check() shows details.",
            ),
            PiiError::Unavailable(_) => Some(
                "Check network access to Vault, pii_vault.url and the TLS settings; transient failures can be retried.",
            ),
            PiiError::InvalidText(_) => Some(
                "piitext literals come from the piitext output function. Use piitext_encrypt(text, bytea) to encrypt a value.",
            ),
            PiiError::StagingDisabled => Some(
                "Encrypt the value with piitext_encrypt(text, bytea), or set pii_vault.allow_staging = on to accept plaintext staging values.",
            ),
            _ => None,
        }
    }

    /// Count the failure in the monitoring counters (see `piitext_stats()`).
    pub(crate) fn record(&self) {
        if matches!(self, PiiError::PermissionDenied(_)) {
            shared::incr(Counter::VaultDenied);
        }
    }

    /// Raise this error as a PostgreSQL `ERROR`. Never returns.
    pub fn raise(self) -> ! {
        self.record();
        let mut report = ErrorReport::new(self.sqlstate(), self.to_string(), "pg_pii_vault");
        if let Some(hint) = self.hint() {
            report = report.set_hint(hint);
        }
        report.report(PgLogLevel::ERROR);
        unreachable!("ERROR report returned")
    }
}

impl fmt::Display for PiiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PiiError::Config(m) => write!(f, "pg_pii_vault configuration error: {m}"),
            PiiError::InvalidArgument(m) => write!(f, "{m}"),
            PiiError::InvalidText(m) => write!(f, "invalid input syntax for type piitext: {m}"),
            PiiError::Corrupted(m) => write!(f, "corrupted piitext value: {m}"),
            PiiError::PermissionDenied(m) => write!(f, "Vault denied the request: {m}"),
            PiiError::Unavailable(m) => write!(f, "Vault is unavailable: {m}"),
            PiiError::Vault(m) => write!(f, "unexpected Vault response: {m}"),
            PiiError::KeyNotFound(m) => write!(f, "encryption key not found in Vault: {m}"),
            PiiError::StagingDisabled => write!(
                f,
                "plaintext piitext values are disabled (pii_vault.allow_staging = off)"
            ),
        }
    }
}

/// Unwrap a result or raise the error as a PostgreSQL `ERROR`.
pub trait OrRaise<T> {
    fn or_raise(self) -> T;
}

impl<T> OrRaise<T> for Result<T, PiiError> {
    fn or_raise(self) -> T {
        match self {
            Ok(v) => v,
            Err(e) => e.raise(),
        }
    }
}

# Security

## Reporting Security Issues

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please open a [security advisory][advisory] to notify the maintainers. You should receive a response within 3 working days. If for some reason you do not, please follow up via email to ensure we received your original message.

Please include the requested information listed below (as much as you can provide) to help us better understand the nature and scope of the possible issue:

  * Type of issue (e.g. buffer overflow, SQL injection, cross-site scripting, etc.)
  * Full paths of source file(s) related to the manifestation of the issue
  * The location of the affected source code (tag/branch/commit or direct URL)
  * Any special configuration required to reproduce the issue
  * Step-by-step instructions to reproduce the issue
  * Proof-of-concept or exploit code (if possible)
  * Impact of the issue, including how an attacker might exploit the issue

This information will help us triage your report more quickly.

If you find a vulnerability anywhere in this project, such as the source or scripts,
then please let the maintainers know ASAP and we will fix it as a critical priority.

## Supported versions

Security fixes are released for the latest version only. Version 0.0.x is not supported: it stores
plaintext silently in several situations and exposes the Vault token to every database role. Upgrade to
the latest 0.1 release as described in [UPGRADING.md](UPGRADING.md).

## Security model

In short:

- A role decrypts only if it has `EXECUTE` on `piitext_out_text(piitext)`. Every other role, including
  members of `pg_read_all_data`, reads ciphertext.
- Superusers, the database host, Vault and whoever holds the extension's Vault token are trusted. In
  `export` key mode, key material is present in backend memory; in `transit` mode it never leaves Vault.
- Deleting a key in Vault (crypto-shredding) makes every value encrypted with it unreadable, in backups
  and replicas too. It does not cover plaintext staging values, plaintext that existed before encryption,
  or keys that were copied out of Vault.
- A value reads as `****` only when its key is gone. Vault outages, permission problems and
  misconfiguration raise errors.

The full threat model, the cryptographic details and a hardening checklist are in
[docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md).

[advisory]: https://github.com/g0ddest/pg_pii_vault/security/advisories/new

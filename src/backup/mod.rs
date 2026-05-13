//! Vault cloud backup — REQ-KVD-CLI-005 (Pro tier).
//!
//! Crypto invariants (D8 SPEC M2):
//!   - Sub-key derivada via HKDF-SHA256 con info `kvendra/backup-cipher/v1`
//!     desde la session key del vault unlocked. NO sale del cliente.
//!   - AES-256-GCM single-shot (M2 decisión: vault realista <5 MiB).
//!   - Bundle layout: tar of vault dir → encrypt → ciphertext+tag.
//!   - Conflict detection optimistic via `parent_version_etag` en manifest.

pub mod bundle;
pub mod client;
pub mod crypto;
pub mod manifest;

pub use bundle::{build_bundle, extract_bundle};
pub use manifest::BackupManifest;

pub const BACKUP_BUNDLE_FORMAT: &str = "tar+aes-gcm-v1";
pub const BACKUP_HKDF_INFO: &[u8] = b"kvendra/backup-cipher/v1";

/// Hard cap per AC-BACKUP-9 + D1 SPEC (API GW HTTP API límite 10 MiB).
pub const BACKUP_MAX_BYTES: u64 = 10 * 1024 * 1024;

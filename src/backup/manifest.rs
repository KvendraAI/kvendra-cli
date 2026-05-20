//! Manifest of a backup version — travels along the encrypted blob as JSON.

use serde::{Deserialize, Serialize};

pub const MANIFEST_VERSION: &str = "kvendra-vault-backup/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    pub version: String,
    pub timestamp_iso: String,
    pub kvendra_cli_version: String,
    pub local_checksum_sha256_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_version_etag: Option<String>,
    pub bundle_size_bytes: u64,
    pub bundle_format: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl BackupManifest {
    pub fn new(
        checksum_sha256_hex: String,
        parent_version_etag: Option<String>,
        bundle_size_bytes: u64,
        label: Option<String>,
    ) -> Self {
        Self {
            version: MANIFEST_VERSION.to_string(),
            timestamp_iso: current_iso8601(),
            kvendra_cli_version: env!("CARGO_PKG_VERSION").to_string(),
            local_checksum_sha256_hex: checksum_sha256_hex,
            parent_version_etag,
            bundle_size_bytes,
            bundle_format: super::BACKUP_BUNDLE_FORMAT.to_string(),
            label,
        }
    }
}

fn current_iso8601() -> String {
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// Metadata returned by `GET /v1/backups` and `POST /v1/backups`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupVersionMeta {
    pub backup_id: String,
    pub version: u64,
    pub etag: String,
    pub created_at: String,
    pub size_bytes: u64,
    #[serde(default)]
    pub kvendra_cli_version: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
}

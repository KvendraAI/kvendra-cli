//! JSON canónico RFC 8785 — source of truth para verificación HMAC.

use crate::audit::export::bundle::ExportBundle;
use crate::error::{KvendraError, KvendraResult};
use std::path::Path;

pub fn write_json(path: &Path, bundle: &ExportBundle) -> KvendraResult<()> {
    let canonical = serde_jcs::to_string(bundle)
        .map_err(|e| KvendraError::Audit(format!("jcs serialize: {e}")))?;
    std::fs::write(path, canonical.as_bytes())?;
    Ok(())
}

pub fn read_json_canonical(path: &Path) -> KvendraResult<ExportBundle> {
    let raw = std::fs::read_to_string(path)?;
    let bundle: ExportBundle = serde_json::from_str(&raw)
        .map_err(|e| KvendraError::Audit(format!("jcs parse: {e}")))?;
    Ok(bundle)
}

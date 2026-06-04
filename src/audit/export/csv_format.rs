//! CSV writer — UTF-8 BOM + columnas AC-EXPORT-2.

use crate::audit::export::bundle::ExportBundle;
use crate::error::{KvendraError, KvendraResult};
use std::path::Path;

pub fn write_csv(path: &Path, bundle: &ExportBundle) -> KvendraResult<()> {
    let mut bytes: Vec<u8> = Vec::new();
    // BOM UTF-8 — Excel compat (AC-EXPORT-2).
    bytes.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
    {
        let mut wtr = csv::WriterBuilder::new().from_writer(&mut bytes);
        wtr.write_record([
            "timestamp_iso8601",
            "profile_id",
            "primitive",
            "op",
            "args_summary",
            "result_status",
            "error_kind",
            "error_message",
            "severity",
            "flags",
            "hmac_chain_id",
            "previous_hmac",
            "current_hmac",
        ])
        .map_err(|e| KvendraError::Audit(format!("csv write header: {e}")))?;

        for ev in &bundle.events {
            let audit_id = ev.audit_id.to_string();
            let ts_ms = ev.ts_unix_ms.to_string();
            // `error_kind` now carries the v3 closed-vocabulary code;
            // `error_message` the sanitized detail. Both empty for non-error
            // and pre-v3 rows.
            wtr.write_record([
                &ev.timestamp_iso8601,
                &ev.profile_id,
                &ev.primitive,
                &ev.action,
                &ev.args_summary,
                &ev.result_status,
                ev.error_code.as_deref().unwrap_or(""),
                ev.error_message.as_deref().unwrap_or(""),
                &ev.severity,
                &ev.flags,
                &audit_id,
                &ev.previous_hmac_hex,
                &ev.current_hmac_hex,
            ])
            .map_err(|e| KvendraError::Audit(format!("csv write row: {e}")))?;
            let _ = ts_ms; // currently unused — reserved for raw ms column
        }
        wtr.flush()
            .map_err(|e| KvendraError::Audit(format!("csv flush: {e}")))?;
    }
    std::fs::write(path, bytes)?;
    Ok(())
}

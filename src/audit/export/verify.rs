//! Verificación de la cadena HMAC recomputándola a partir del JSON canónico.

use crate::audit::export::bundle::ExportBundle;
use crate::audit::export::json_canonical::read_json_canonical;
use crate::audit::hmac::{compute_hmac_v1, compute_hmac_v2};
use crate::error::{KvendraError, KvendraResult};
use std::path::Path;

#[derive(Debug, Clone)]
pub enum VerifyOutcome {
    Pass {
        events_count: usize,
    },
    Fail {
        first_deviation_at: usize,
        reason: String,
    },
}

/// Derive the chain HMAC key from the public seed embedded in the export.
///
/// The seed is a `hex(audit_hmac_subkey)` — exposing it does NOT compromise
/// vault secrets (the seed only allows verifying integrity of the captured
/// snapshot; it cannot be used to forge new audit events that respect the
/// vault's internal chain because the local `audit.db` lives behind the
/// master password gate).
pub fn derive_chain_key_from_seed(seed_hex: &str) -> KvendraResult<Vec<u8>> {
    hex::decode(seed_hex).map_err(|e| KvendraError::Audit(format!("seed hex decode: {e}")))
}

pub fn verify_bundle(bundle: &ExportBundle) -> KvendraResult<VerifyOutcome> {
    if bundle.version != super::bundle::EXPORT_VERSION {
        return Ok(VerifyOutcome::Fail {
            first_deviation_at: 0,
            reason: format!("unsupported export version: {}", bundle.version),
        });
    }
    let key = derive_chain_key_from_seed(&bundle.chain_key_seed_hex)?;
    let mut prev = bundle.chain_root_hmac_hex.clone();

    for (i, ev) in bundle.events.iter().enumerate() {
        if ev.previous_hmac_hex != prev {
            return Ok(VerifyOutcome::Fail {
                first_deviation_at: i,
                reason: format!(
                    "previous_hmac mismatch at row {} (audit_id={})",
                    i, ev.audit_id
                ),
            });
        }
        let recomputed = if ev.hmac_version >= 2 {
            compute_hmac_v2(
                &key,
                ev.audit_id,
                ev.ts_unix_ms,
                &ev.profile_id,
                &ev.primitive,
                &ev.action,
                &ev.args_hash_hex,
                &ev.result_status,
                &ev.severity,
                &ev.flags,
                &ev.previous_hmac_hex,
                ev.remote_audit_id.as_deref(),
            )
        } else {
            compute_hmac_v1(
                &key,
                ev.audit_id,
                ev.ts_unix_ms,
                &ev.profile_id,
                &ev.primitive,
                &ev.action,
                &ev.args_hash_hex,
                &ev.result_status,
                &ev.severity,
                &ev.flags,
                &ev.previous_hmac_hex,
            )
        };
        if recomputed != ev.current_hmac_hex {
            return Ok(VerifyOutcome::Fail {
                first_deviation_at: i,
                reason: format!(
                    "current_hmac mismatch at row {} (audit_id={})",
                    i, ev.audit_id
                ),
            });
        }
        prev = ev.current_hmac_hex.clone();
    }
    if prev != bundle.chain_end_hmac_hex && !bundle.events.is_empty() {
        return Ok(VerifyOutcome::Fail {
            first_deviation_at: bundle.events.len(),
            reason: "chain_end_hmac mismatch".to_string(),
        });
    }
    Ok(VerifyOutcome::Pass {
        events_count: bundle.events.len(),
    })
}

pub fn verify_path(path: &Path) -> KvendraResult<VerifyOutcome> {
    let bundle = read_json_canonical(path)?;
    verify_bundle(&bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::export::bundle::{EXPORT_VERSION, ExportFilters, build_bundle};
    use crate::audit::hmac::compute_hmac_v2;
    use crate::audit::reader::StoredEvent;

    /// Generate a synthetic 3-row HMAC chain under a known key.
    fn synth_chain(key: &[u8]) -> Vec<StoredEvent> {
        let mut events = Vec::new();
        let mut prev = String::new();
        for i in 1..=3i64 {
            let ev = StoredEvent {
                id: i,
                ts_unix_ms: 1_700_000_000_000 + i,
                profile_id: format!("p{i}"),
                primitive: "kvendra.git".into(),
                action: "clone".into(),
                args_hash_hex: format!("{:064x}", i),
                status: "ok".into(),
                severity: "info".into(),
                flags: String::new(),
                prev_hmac_hex: prev.clone(),
                hmac_hex: String::new(),
                remote_audit_id: None,
                hmac_version: 2,
            };
            let h = compute_hmac_v2(
                key,
                ev.id,
                ev.ts_unix_ms,
                &ev.profile_id,
                &ev.primitive,
                &ev.action,
                &ev.args_hash_hex,
                &ev.status,
                &ev.severity,
                &ev.flags,
                &ev.prev_hmac_hex,
                None,
            );
            let mut full = ev;
            full.hmac_hex = h.clone();
            prev = h;
            events.push(full);
        }
        events
    }

    #[test]
    fn roundtrip_pass() {
        let key = [9u8; 32];
        let events = synth_chain(&key);
        let bundle = build_bundle(
            &events,
            "Test Suite",
            ExportFilters {
                from: None,
                to: None,
                raw: None,
            },
            hex::encode(key),
        );
        assert_eq!(bundle.version, EXPORT_VERSION);
        let outcome = verify_bundle(&bundle).expect("verify");
        match outcome {
            VerifyOutcome::Pass { events_count } => assert_eq!(events_count, 3),
            VerifyOutcome::Fail { reason, .. } => panic!("expected PASS, got {reason}"),
        }
    }

    #[test]
    fn tampered_event_fails() {
        let key = [9u8; 32];
        let events = synth_chain(&key);
        let mut bundle = build_bundle(
            &events,
            "Test Suite",
            ExportFilters {
                from: None,
                to: None,
                raw: None,
            },
            hex::encode(key),
        );
        // Mutate the middle event's action — HMAC chain MUST detect.
        bundle.events[1].action = "push".into();
        let outcome = verify_bundle(&bundle).expect("verify");
        match outcome {
            VerifyOutcome::Pass { .. } => panic!("expected FAIL on tampered row"),
            VerifyOutcome::Fail {
                first_deviation_at, ..
            } => assert_eq!(first_deviation_at, 1),
        }
    }

    #[test]
    fn wrong_seed_fails() {
        let key = [9u8; 32];
        let events = synth_chain(&key);
        let mut bundle = build_bundle(
            &events,
            "Test Suite",
            ExportFilters {
                from: None,
                to: None,
                raw: None,
            },
            hex::encode(key),
        );
        // Wrong seed — every HMAC will mismatch.
        bundle.chain_key_seed_hex = hex::encode([0u8; 32]);
        let outcome = verify_bundle(&bundle).expect("verify");
        assert!(matches!(outcome, VerifyOutcome::Fail { .. }));
    }
}

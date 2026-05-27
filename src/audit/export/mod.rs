//! Audit export — PDF/CSV/JSON canónico con cadena HMAC firmada.
//!
//! Implementa REQ-KVD-CLI-007 (AC-EXPORT-1..7). Decisión D10/D11 del SPEC M2:
//!  - JSON canónico RFC 8785 vía `serde_jcs`.
//!  - PDF vía `printpdf` (pure-Rust).
//!  - CSV con BOM UTF-8.
//!  - Privacy redaction por defecto sobre `args_hash` y flags.
//!  - El export incluye `chain_key_seed_hex` para que el verifier público
//!    `https://app.kvendra.cloud/audit-verify` recompute la cadena sin
//!    necesitar acceso al vault. La sub-key se deriva del seed mediante un
//!    HKDF determinista — el seed NO es secret material (solo permite
//!    verificar integridad post-export, no falsificar nuevos eventos).

pub mod bundle;
pub mod csv_format;
pub mod filter;
pub mod json_canonical;
pub mod pdf_format;
pub mod redaction;
pub mod verify;

pub use bundle::{BRAND_DEFAULT, EXPORT_VERSION, ExportBundle, ExportedEvent, build_bundle};
pub use verify::{VerifyOutcome, verify_bundle};

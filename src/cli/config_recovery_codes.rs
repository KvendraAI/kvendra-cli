//! `kvendra config recovery-codes <subcommand>` — manage recovery codes.
//!
//! REQ-KVD-CLI-003 / ISSUE-KVD-CLI-025 — Currently exposes the `regenerate`
//! subcommand which atomically rotates the 8 numeric one-time codes stored
//! in `~/.kvendra/recovery_codes.json` (Argon2id-hashed, 0600).
//!
//! ## Double-barrier policy (variant of PAT-KVD-008 rebind pattern)
//!
//! Unlike `rebind-home` (triple barrier), `regenerate` is a CREATE op — it
//! does not defend a scarce resource (each rotation simply replaces the
//! previous batch). Consuming a recovery code here would create a deadlock
//! when the user is regenerating *because* their codes are exhausted. So
//! the flow uses TWO barriers instead of three:
//!
//! 1. **Master password unlock** (`Vault::unlock`).
//! 2. **TTY re-typed acknowledge** — the literal string
//!    `REGENERATE-RECOVERY-CODES` (case-sensitive, byte-exact). No
//!    `[y/N]` shortcut; the policy mirrors the rebind UX so dangerous
//!    operations always demand a deliberate keystroke sequence.
//!
//! Strict no-TTY policy (parity with rebind D4=A): if `stdin` is not a
//! terminal, the command rejects with [`KvendraError::RegenerateRequiresTty`].
//!
//! ## Audit row schema (D8 parity)
//!
//! | field        | value                                                                    |
//! |--------------|--------------------------------------------------------------------------|
//! | primitive    | `kvendra.system`                                                         |
//! | action       | `recovery_codes_regenerate`                                              |
//! | severity     | `warn`                                                                   |
//! | status       | `ok` (success) / `error` (acknowledge mismatch)                          |
//! | flags        | `recovery_codes_regenerated,previous_used_count_<N>` on success, or      |
//! |              | `recovery_codes_regenerate_aborted_acknowledge_mismatch` on abort        |
//! | args_hash    | `sha256(ts_ms | previous_used_count)` — never includes a recovery code   |

use crate::audit::{AuditEvent, AuditWriter, PRIMITIVE_SYSTEM, Severity, Status};
use crate::config::{ensure_layout, kvendra_home, set_file_mode_secure};
use crate::error::{KvendraError, KvendraResult};
use crate::vault::Vault;
use crate::vault::kdf::{KdfParams, derive, random_salt};
use crate::vault::recovery::{RecoveryCodesFile, StoredCode, generate_codes};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use clap::{Args, Subcommand};
use sha2::{Digest, Sha256};
use std::io::IsTerminal;
use std::path::Path;
use zeroize::Zeroize;

/// Literal string the user must re-type (byte-exact, case-sensitive) to
/// confirm a regenerate operation.
pub const REGENERATE_ACK: &str = "REGENERATE-RECOVERY-CODES";

#[derive(Debug, Subcommand)]
pub enum RecoveryCodesCommand {
    /// Regenerate the 8 numeric one-time recovery codes. Double-barrier:
    /// master password + TTY re-typed acknowledge `REGENERATE-RECOVERY-CODES`.
    Regenerate(RegenerateArgs),
}

#[derive(Debug, Args)]
pub struct RegenerateArgs {
    /// Skip the interactive TTY confirmation step. Reserved for tests; the
    /// production CLI rejects non-TTY invocations regardless of this flag.
    #[cfg(test)]
    #[arg(long, hide = true)]
    pub test_assume_tty: bool,
}

#[cfg(not(test))]
impl RegenerateArgs {
    fn assume_tty_override(&self) -> bool {
        false
    }
}

#[cfg(test)]
impl RegenerateArgs {
    fn assume_tty_override(&self) -> bool {
        self.test_assume_tty
    }
}

/// Outcome of a successful `regenerate_inner` call. Surfaced to the CLI
/// shell for stdout messaging and consumed by integration tests.
#[derive(Debug)]
pub struct RegenerateOutcome {
    /// The freshly-generated plaintext codes (caller is expected to render
    /// them to the user once and drop the vector — minimize window of
    /// exposure). The hashed copy has already been persisted to disk.
    pub new_codes: Vec<String>,
    /// Number of slots in the previous file that carried `used_at = Some(_)`.
    /// Recorded in the audit row's `flags` for forensic insight.
    pub previous_used_count: usize,
}

pub async fn run(cmd: RecoveryCodesCommand) -> KvendraResult<()> {
    match cmd {
        RecoveryCodesCommand::Regenerate(args) => run_regenerate(args).await,
    }
}

async fn run_regenerate(args: RegenerateArgs) -> KvendraResult<()> {
    let home = kvendra_home()?;
    ensure_layout(&home)?;

    // Strict no-TTY policy (parity with rebind D4=A).
    if !args.assume_tty_override() && !std::io::stdin().is_terminal() {
        return Err(KvendraError::RegenerateRequiresTty);
    }

    // Read master password (env-var honoured for non-interactive automation
    // scripts that pipe both the password AND the acknowledge string).
    let password = match std::env::var("KVENDRA_PASSWORD") {
        Ok(s) => s,
        Err(_) => rpassword::prompt_password("[1/2] Master password (will not echo): ")
            .map_err(|e| KvendraError::Vault(format!("read password: {e}")))?,
    };

    // Warning banner BEFORE the typed-acknowledge prompt.
    println!();
    println!(
        "[2/2] Confirm recovery codes regeneration. The following side-effects WILL be applied:"
    );
    println!("      - All 8 existing recovery codes will be INVALIDATED.");
    println!("      - 8 new codes will be generated and shown ONCE on stdout.");
    println!("      - recovery_codes.json will be overwritten atomically (0600).");
    println!("      - audit row 'recovery_codes_regenerate' (severity=warn) appended.");
    println!();
    println!(
        "Type the literal string '{REGENERATE_ACK}' (case-sensitive) to confirm:"
    );

    let mut typed = String::new();
    std::io::stdin()
        .read_line(&mut typed)
        .map_err(|e| KvendraError::Config(format!("read confirmation: {e}")))?;
    let typed = typed.trim_end_matches(['\r', '\n']);

    let outcome = regenerate_inner(&home, password.as_bytes(), typed).await?;

    // Render the new codes ONCE.
    println!();
    println!("════════════════════════════════════════════════════════════════");
    println!(
        "  NEW Recovery codes — SAVE THESE NOW. They will not be shown again."
    );
    println!("════════════════════════════════════════════════════════════════");
    println!();
    println!("Numeric one-time codes ({} codes):", outcome.new_codes.len());
    for code in &outcome.new_codes {
        println!("    {code}");
    }
    println!();
    println!("════════════════════════════════════════════════════════════════");
    println!(
        "Previous codes (used: {}) have been invalidated.",
        outcome.previous_used_count
    );

    // Best-effort minimization of exposure window in process memory. The
    // String contents themselves aren't pinned, but dropping the Vec drops
    // each String which deallocates its buffer.
    drop(outcome.new_codes);
    Ok(())
}

/// Testable core of the double-barrier regenerate flow. Side-effects are
/// committed in this exact order:
/// 1. `Vault::unlock` (master password barrier — Barrera 1).
/// 2. Acknowledge string byte-exact compare (Barrera 2).
///    On mismatch: emit a dedicated `recovery_codes_regenerate` audit row
///    with `status = error` + `flags = recovery_codes_regenerate_aborted_acknowledge_mismatch`,
///    THEN return [`KvendraError::RegenerateAcknowledgeMismatch`].
/// 3. Read previous `recovery_codes.json` into a buffer + count `used_at = Some` slots.
/// 4. Generate 8 new codes (`recovery::generate_codes`) and Argon2id-hash
///    each with the same params used by `init` (m=19_456 KiB, t=2, p=1).
/// 5. Atomic write-then-rename to `recovery_codes.json` with 0600 perms.
/// 6. Zeroize the previous-file buffer (defence-in-depth — the previous
///    codes were already only stored as Argon2id hashes, so this is just
///    paranoia for any in-RAM forensic footprint).
/// 7. Emit success audit row (severity=warn, status=ok).
pub async fn regenerate_inner(
    home: &Path,
    master_password: &[u8],
    typed_acknowledge: &str,
) -> KvendraResult<RegenerateOutcome> {
    // Vault setup.
    let vault = Vault::new(home.to_path_buf());
    if !vault.sentinel_path().exists() {
        return Err(KvendraError::Vault(
            "vault not initialized — run `kvendra init` first".into(),
        ));
    }

    // Barrier 1 — master password unlock. Wrong password short-circuits
    // BEFORE the acknowledge check (so a typo in the password does not
    // emit an `acknowledge_mismatch` audit row, which would be misleading).
    vault.unlock(master_password, 30)?;

    // Barrier 2 — acknowledge byte-exact compare. The audit row is emitted
    // AFTER unlock because writing to the audit log requires the HKDF
    // sub-key derived during `unlock`. AC-3 of REQ-KVD-CLI-003: the
    // typed string itself is NOT included in any field — only an
    // acknowledge_mismatch flag.
    if typed_acknowledge != REGENERATE_ACK {
        let writer = AuditWriter::spawn(vault.audit_db_path(), vault.audit_hmac_key()?)?;
        let now_ms = current_ms();
        let args_hash = sha256_hex(format!("{now_ms}|acknowledge_mismatch"));
        writer
            .record(AuditEvent {
                ts_unix_ms: now_ms,
                profile_id: String::new(),
                primitive: PRIMITIVE_SYSTEM.to_string(),
                action: "recovery_codes_regenerate".to_string(),
                args_hash_hex: args_hash,
                status: Status::Error,
                severity: Severity::Warn,
                flags: "recovery_codes_regenerate_aborted_acknowledge_mismatch".to_string(),
                remote_audit_id: None,
            })
            .await?;
        writer.shutdown().await;
        return Err(KvendraError::RegenerateAcknowledgeMismatch);
    }

    // Read previous file into a buffer and count consumed slots.
    let codes_path = vault.recovery_codes_path();
    let mut previous_buf: Vec<u8> = if codes_path.exists() {
        std::fs::read(&codes_path)?
    } else {
        Vec::new()
    };
    let previous_used_count = if previous_buf.is_empty() {
        0
    } else {
        let parsed: RecoveryCodesFile = serde_json::from_slice(&previous_buf)?;
        parsed.codes.iter().filter(|c| c.used_at.is_some()).count()
    };

    // Generate 8 fresh codes + Argon2id-hash with bit-exact init params.
    let new_codes = generate_codes();
    let mut stored = RecoveryCodesFile::default();
    for code in &new_codes {
        let salt = random_salt();
        let params = KdfParams {
            m_cost_kib: 19_456,
            t_cost: 2,
            p_cost: 1,
            salt: salt.clone(),
        };
        let h = derive(code.as_bytes(), &params)?;
        stored.codes.push(StoredCode {
            hash_b64: B64.encode(h.as_bytes()),
            salt_b64: B64.encode(&salt),
            used_at: None,
            used_for: None,
        });
    }

    // Atomic write-then-rename + 0600 perms (parity with rebind path).
    let tmp = codes_path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(&stored)?)?;
    set_file_mode_secure(&tmp)?;
    std::fs::rename(&tmp, &codes_path)?;
    set_file_mode_secure(&codes_path)?;

    // Zeroize the previous-file buffer. The previous codes were only stored
    // as Argon2id hashes (not plaintext), so this is defence-in-depth for
    // RAM forensics rather than a strict secrecy requirement.
    previous_buf.zeroize();
    drop(previous_buf);

    // Success audit row (D8 schema, severity=warn).
    let writer = AuditWriter::spawn(vault.audit_db_path(), vault.audit_hmac_key()?)?;
    let now_ms = current_ms();
    let args_hash = sha256_hex(format!("{now_ms}|{previous_used_count}"));
    writer
        .record(AuditEvent {
            ts_unix_ms: now_ms,
            profile_id: String::new(),
            primitive: PRIMITIVE_SYSTEM.to_string(),
            action: "recovery_codes_regenerate".to_string(),
            args_hash_hex: args_hash,
            status: Status::Ok,
            severity: Severity::Warn,
            flags: format!(
                "recovery_codes_regenerated,previous_used_count_{previous_used_count}"
            ),
            remote_audit_id: None,
        })
        .await?;
    writer.shutdown().await;

    Ok(RegenerateOutcome {
        new_codes,
        previous_used_count,
    })
}

fn current_ms() -> i64 {
    (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64
}

fn sha256_hex(s: impl AsRef<[u8]>) -> String {
    let mut h = Sha256::new();
    h.update(s.as_ref());
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use tempfile::TempDir;

    fn fast_params() -> KdfParams {
        KdfParams {
            m_cost_kib: 19_456,
            t_cost: 2,
            p_cost: 1,
            salt: vec![1u8; 16],
        }
    }

    /// Bootstrap a fresh `~/.kvendra/`-shaped tempdir with an unlocked vault
    /// AND a `recovery_codes.json` that mirrors `kvendra init`'s layout: 8
    /// Argon2id-hashed codes, all unconsumed.
    fn bootstrap_vault_with_8_codes(home: &Path) -> (Vault, Vec<String>) {
        ensure_layout(home).unwrap();
        let v = Vault::new(home.to_path_buf());
        v.create_with_params(b"hunter2-test", fast_params()).unwrap();
        v.unlock(b"hunter2-test", 30).unwrap();

        let codes = generate_codes();
        let mut stored = RecoveryCodesFile::default();
        for code in &codes {
            let salt = random_salt();
            let params = KdfParams {
                m_cost_kib: 19_456,
                t_cost: 2,
                p_cost: 1,
                salt: salt.clone(),
            };
            let h = derive(code.as_bytes(), &params).unwrap();
            stored.codes.push(StoredCode {
                hash_b64: B64.encode(h.as_bytes()),
                salt_b64: B64.encode(&salt),
                used_at: None,
                used_for: None,
            });
        }
        std::fs::write(
            v.recovery_codes_path(),
            serde_json::to_string_pretty(&stored).unwrap(),
        )
        .unwrap();
        Config::default().save(home, &v).unwrap();
        (v, codes)
    }

    /// Smoke: happy path returns 8 codes and previous_used_count = 0.
    #[tokio::test]
    async fn regenerate_inner_happy_path_returns_8_codes() {
        let tmp = TempDir::new().unwrap();
        let (_v, _codes) = bootstrap_vault_with_8_codes(tmp.path());
        let outcome = regenerate_inner(tmp.path(), b"hunter2-test", REGENERATE_ACK)
            .await
            .unwrap();
        assert_eq!(outcome.new_codes.len(), 8);
        assert_eq!(outcome.previous_used_count, 0);
    }

    /// Wrong password rejects with InvalidMasterPassword BEFORE acknowledge
    /// is checked.
    #[tokio::test]
    async fn regenerate_inner_wrong_password_rejects() {
        let tmp = TempDir::new().unwrap();
        let (_v, _codes) = bootstrap_vault_with_8_codes(tmp.path());
        let r = regenerate_inner(tmp.path(), b"WRONG-PASSWORD", REGENERATE_ACK).await;
        assert!(matches!(r, Err(KvendraError::InvalidMasterPassword)));
    }

    /// Acknowledge mismatch rejects AFTER unlock and emits the dedicated
    /// audit row.
    #[tokio::test]
    async fn regenerate_inner_acknowledge_mismatch_rejects() {
        let tmp = TempDir::new().unwrap();
        let (_v, _codes) = bootstrap_vault_with_8_codes(tmp.path());
        let r = regenerate_inner(tmp.path(), b"hunter2-test", "regenerate").await;
        assert!(matches!(r, Err(KvendraError::RegenerateAcknowledgeMismatch)));
    }
}

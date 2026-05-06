//! `kvendra init` — vault bootstrap with full recovery UX (ADR-KVD-011).

use crate::config::{Config, ensure_layout, kvendra_home};
use crate::error::{KvendraError, KvendraResult};
use crate::vault::Vault;
use crate::vault::recovery::{RecoveryCodesFile, StoredCode, generate_codes, generate_mnemonic};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use clap::Args;
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Skip the interactive verification step (testing only).
    #[arg(long)]
    pub no_verify: bool,
    /// Read the master password from this env var instead of prompting.
    #[arg(long, env = "KVENDRA_INIT_PASSWORD")]
    pub password_env: Option<String>,
    /// Pre-confirmation code (for non-interactive setups).
    #[arg(long, env = "KVENDRA_INIT_CONFIRM_CODE")]
    pub confirm_code: Option<String>,
    /// Save recovery codes (mnemonic + numeric) to this path (warns about 0600).
    #[arg(long)]
    pub save_to: Option<PathBuf>,
    /// Override kvendra home (testing).
    #[arg(long, env = "KVENDRA_HOME")]
    pub home_override: Option<PathBuf>,
}

pub async fn run(args: InitArgs) -> KvendraResult<()> {
    let home = args
        .home_override
        .clone()
        .map(Ok)
        .unwrap_or_else(kvendra_home)?;
    ensure_layout(&home)?;
    let cfg = Config::default();
    cfg.save(&home)?;

    let vault = Vault::new(home.clone());
    if vault.sentinel_path().exists() {
        return Err(KvendraError::Vault(
            "vault already initialized. Use `kvendra recover` to rotate the master password."
                .into(),
        ));
    }

    let password = match args.password_env {
        Some(s) => s,
        None => {
            println!("Enter a master password (will not echo):");
            rpassword::read_password()
                .map_err(|e| KvendraError::Vault(format!("read password: {e}")))?
        }
    };
    if password.len() < 8 {
        return Err(KvendraError::Vault(
            "master password must be ≥ 8 characters".into(),
        ));
    }

    // Generate recovery material BEFORE creating the vault. If anything
    // fails between here and the verification step, the entire flow is a
    // no-op (transactional cleanup).
    let mnemonic = generate_mnemonic()?;
    let codes = generate_codes();

    println!();
    println!("════════════════════════════════════════════════════════════════");
    println!("  Recovery material — SAVE THESE NOW. They will not be shown again.");
    println!("════════════════════════════════════════════════════════════════");
    println!();
    println!("BIP-39 mnemonic (12 words):");
    println!("    {mnemonic}");
    println!();
    println!("Numeric one-time codes (8 codes):");
    for c in &codes {
        println!("    {c}");
    }
    println!();
    println!("════════════════════════════════════════════════════════════════");
    println!();

    // Optional save-to file.
    if let Some(path) = &args.save_to {
        let mut content = String::new();
        content.push_str("# kvendra recovery codes — KEEP THIS FILE OFFLINE\n");
        content.push_str(&format!("mnemonic: {mnemonic}\n"));
        content.push_str("codes:\n");
        for c in &codes {
            content.push_str(&format!("  - {c}\n"));
        }
        std::fs::write(path, content)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }
        println!("Recovery material written to {} (0600).", path.display());
    }

    // Pre-confirmation step (AC-VAULT-3).
    if !args.no_verify {
        let entered = match args.confirm_code {
            Some(s) => s,
            None => {
                println!(
                    "To confirm you saved the recovery codes, enter ANY of the 8 numeric codes:"
                );
                let mut buf = String::new();
                std::io::stdin()
                    .read_line(&mut buf)
                    .map_err(|e| KvendraError::Vault(format!("read confirm: {e}")))?;
                buf.trim().to_string()
            }
        };
        if !codes.iter().any(|c| c == &entered) {
            // Transactional cleanup: nothing has been written to the vault yet.
            return Err(KvendraError::Vault(
                "confirmation code did not match a generated recovery code — init aborted".into(),
            ));
        }
    }

    // Persist hashed codes for later one-shot use.
    let mut stored = RecoveryCodesFile::default();
    for code in &codes {
        // Hash with Argon2id (params here: very fast — these are 10-digit codes,
        // not high-entropy material; we still hash them and salt per-code).
        let salt = crate::vault::kdf::random_salt();
        let params = crate::vault::kdf::KdfParams {
            m_cost_kib: 19_456,
            t_cost: 2,
            p_cost: 1,
            salt: salt.clone(),
        };
        let h = crate::vault::kdf::derive(code.as_bytes(), &params)?;
        stored.codes.push(StoredCode {
            hash_b64: B64.encode(h.as_bytes()),
            salt_b64: B64.encode(&salt),
            used_at: None,
            used_for: None,
        });
    }
    let codes_path = vault.recovery_codes_path();
    std::fs::write(&codes_path, serde_json::to_string_pretty(&stored)?)?;
    // The hashed recovery codes file holds salted Argon2id hashes of the
    // numeric one-shot codes. Even though the codes are themselves hashed,
    // we still tighten the permissions to 0600 to keep them out of reach of
    // other local accounts (defence-in-depth — see THREAT-MODEL V2).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&codes_path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&codes_path, perms)?;
    }

    // Create the vault sentinel.
    vault.create(password.as_bytes())?;

    println!("Vault initialized at {}", home.display());
    Ok(())
}

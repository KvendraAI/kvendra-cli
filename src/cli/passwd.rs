//! `kvendra passwd` — change the master password knowing the current one
//! (REQ-KVD-CLI-CFB449 F5 / AC-REC-14, ADR-KVD-CLI-4810AF).
//!
//! Re-wraps the vault key under the new password with the same atomic commit
//! as `kvendra recover` ([`crate::rekey::commit_new_password`]): sessions
//! and keychain caches are invalidated, nothing else on disk changes.

use crate::captured_env::ensure_real_terminal;
use crate::config::kvendra_home;
use crate::error::{KvendraError, KvendraResult};
use crate::rekey::{caches_for_process, change_password};
use crate::vault::Vault;
use clap::Args;
use zeroize::Zeroizing;

/// Printed after a successful change.
pub const SUCCESS_MESSAGE: &str = "Master password changed. Your secrets, local variables, allowlists, grants and \
     backups keep working. Active sessions and the keychain cache were cleared; any running \
     `kvendra mcp serve` keeps its in-memory session until it expires — restart it. Old copies \
     of sentinel.blob (for example inside earlier backups) still open with the OLD password: \
     if you suspect it was stolen, create a new vault instead.";

#[derive(Debug, Args)]
pub struct PasswdArgs {
    /// Current master password from this env var (testing/CI only; needs
    /// `KVENDRA_NEW_PASSWORD` too, otherwise a real terminal is required).
    #[arg(long, env = "KVENDRA_PASSWORD", hide_env_values = true)]
    pub password_env: Option<String>,
    /// New master password from this env var (testing/CI only).
    #[arg(long, env = "KVENDRA_NEW_PASSWORD", hide_env_values = true)]
    pub new_password_env: Option<String>,
}

pub async fn run(args: PasswdArgs) -> KvendraResult<()> {
    let home = kvendra_home()?;
    let vault = Vault::new(home);
    let caches = caches_for_process()?;

    let (current, new) = match (args.password_env, args.new_password_env) {
        (Some(cur), Some(new)) => (Some(Zeroizing::new(cur)), Some(Zeroizing::new(new))),
        _ => (None, None),
    };
    // Anti-captured-env defense (PAT-KVD-CLI-008), same as `kvendra unlock`:
    // without BOTH env vars the passwords are read from the real terminal.
    let tty = if current.is_none() {
        // Fail early (before the TTY) on states that refuse anyway.
        crate::rekey::passwd_preflight(&vault)?;
        match ensure_real_terminal() {
            Ok(h) => Some(h),
            Err(rejection) => {
                eprintln!("{}", rejection.render());
                return Err(KvendraError::Vault(format!(
                    "passwd refused: {}",
                    rejection.audit_flag()
                )));
            }
        }
    } else {
        None
    };
    let tty_ref = tty.as_ref();
    change_password(
        &vault,
        move || match current {
            Some(p) => Ok(p),
            None => tty_ref
                .expect("tty set when env is absent")
                .read_password("Current master password (will not echo): ")
                .map(Zeroizing::new)
                .map_err(|e| KvendraError::Vault(format!("read password: {e}"))),
        },
        move || match new {
            Some(p) => Ok(p),
            None => {
                let h = tty_ref.expect("tty set when env is absent");
                let a = Zeroizing::new(
                    h.read_password("New master password (will not echo): ")
                        .map_err(|e| KvendraError::Vault(format!("read password: {e}")))?,
                );
                let b = Zeroizing::new(
                    h.read_password("Confirm new master password: ")
                        .map_err(|e| KvendraError::Vault(format!("read password: {e}")))?,
                );
                if !bool::from(subtle::ConstantTimeEq::ct_eq(a.as_bytes(), b.as_bytes())) {
                    return Err(KvendraError::Vault(
                        "new password and confirmation do not match — nothing was changed".into(),
                    ));
                }
                Ok(a)
            }
        },
        caches.as_ref(),
    )
    .await?;
    println!("{SUCCESS_MESSAGE}");
    Ok(())
}

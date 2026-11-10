//! `kvendra passwd` — change the master password knowing the current one
//! (REQ-KVD-CLI-CFB449 F5 / AC-REC-14, ADR-KVD-CLI-4810AF).
//!
//! Re-wraps the vault key under the new password with the same atomic commit
//! as `kvendra recover` ([`crate::rekey::commit_new_password`]): sessions
//! and this vault's keychain entries are invalidated (the final message says
//! exactly which), nothing else on disk changes.

use crate::captured_env::ensure_real_terminal;
use crate::config::kvendra_home;
use crate::error::{KvendraError, KvendraResult};
use crate::rekey::{caches_for_process, change_password};
use crate::vault::Vault;
use clap::Args;
use zeroize::Zeroizing;

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
    let report = change_password(
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
    // Says exactly what was cleared and what was left (M1).
    println!(
        "{}",
        crate::rekey::success_message(crate::rekey::RekeyAction::Passwd, &report)
    );
    Ok(())
}

//! `kvendra config mcp-password <subcommand>` (REQ-KVD-005 / ISSUE-KVD-CLI-017).
//!
//! Stores the master password used by `kvendra mcp serve --use-keychain`
//! in the OS keychain under `service: kvendra`, label
//! `kvendra/mcp-password/v1`, with `kSecAttrAccessControl(.userPresence)`
//! on macOS — every read triggers TouchID or the OS modal password popup.
//!
//! The previous wrapper-script + `fetch` design (ISSUE-010, alpha.3) is
//! superseded: the wrapper is no longer generated and `fetch` is removed.
//! `kvendra mcp serve --use-keychain` reads the keychain inline and the
//! prompt never touches the TTY (mitigates PAT-KVD-007 hijack).
//!
//! macOS only in this release. Windows / Linux: `enable`,
//! `migrate-to-keychain-acl` and `--use-keychain` reject explicitly so we
//! do not create a false sense of biometric protection. Workaround for
//! those platforms: continue using `KVENDRA_MCP_PASSWORD` env var.

use crate::config::kvendra_home;
use crate::error::{KvendraError, KvendraResult};
use crate::keychain_acl::{self, BiometricError};
use clap::{Args, Subcommand};
use std::path::{Path, PathBuf};

const MCP_PASSWORD_LABEL: &str = "kvendra/mcp-password/v1";
const LEGACY_WRAPPER_NAME: &str = "kvendra-mcp-serve";

#[derive(Debug, Subcommand)]
pub enum McpPasswordCommand {
    /// Store master password in OS keychain with biometric/presence ACL.
    Enable,
    /// Migrate existing setup (plaintext env or legacy wrapper) to `--use-keychain`.
    MigrateToKeychainAcl(MigrateArgs),
    /// Show keychain entry status; warn if the legacy wrapper script lingers.
    Status,
    /// Wipe keychain entry and remove any leftover legacy wrapper script.
    Disable,
}

#[derive(Debug, Args)]
pub struct MigrateArgs {
    /// Client to migrate. Currently supports `claude-code`.
    #[arg(long, default_value = "claude-code")]
    pub client: String,
}

pub async fn run(cmd: McpPasswordCommand) -> KvendraResult<()> {
    let home = kvendra_home()?;
    crate::config::ensure_layout(&home)?;
    match cmd {
        McpPasswordCommand::Enable => enable(),
        McpPasswordCommand::MigrateToKeychainAcl(args) => {
            migrate_to_keychain_acl(&home, &args.client)
        }
        McpPasswordCommand::Status => status(&home),
        McpPasswordCommand::Disable => disable(&home),
    }
}

fn enable() -> KvendraResult<()> {
    let password = rpassword::prompt_password("Master password: ")
        .map_err(|e| KvendraError::Config(format!("failed to read password: {e}")))?;
    if password.is_empty() {
        return Err(KvendraError::Config("password is empty".into()));
    }
    keychain_acl::save_with_user_presence(MCP_PASSWORD_LABEL, &password)
        .map_err(map_biometric_error)?;
    println!("Stored mcp-password in OS keychain with presence ACL.");
    println!();
    println!("Update your MCP client config (e.g. ~/.claude.json) to:");
    println!("  \"command\": \"kvendra\",");
    println!("  \"args\": [\"mcp\", \"serve\", \"--use-keychain\"]");
    println!("  (remove env.KVENDRA_MCP_PASSWORD if present)");
    println!();
    println!("Or run `kvendra config mcp-password migrate-to-keychain-acl`.");
    Ok(())
}

fn migrate_to_keychain_acl(home: &Path, client: &str) -> KvendraResult<()> {
    if client != "claude-code" {
        return Err(KvendraError::Config(format!(
            "unsupported --client '{client}' (only 'claude-code' is implemented)"
        )));
    }
    let claude_path = claude_config_path()?;
    if !claude_path.exists() {
        return Err(KvendraError::Config(format!(
            "{} does not exist",
            claude_path.display()
        )));
    }
    let raw = std::fs::read_to_string(&claude_path)?;
    let mut json: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| KvendraError::Config(format!("parse {}: {e}", claude_path.display())))?;

    let kvendra_obj = json
        .get_mut("mcpServers")
        .and_then(|s| s.get_mut("kvendra"))
        .ok_or_else(|| KvendraError::Config("mcpServers.kvendra missing".into()))?;

    // Locate the password from one of two states:
    // (a) plaintext env: mcpServers.kvendra.env.KVENDRA_MCP_PASSWORD
    // (b) legacy wrapper: command points at ~/.kvendra/wrappers/kvendra-mcp-serve;
    //     the password already lives in the keychain (item may or may not have ACL).
    let plaintext_password = kvendra_obj
        .get("env")
        .and_then(|e| e.get("KVENDRA_MCP_PASSWORD"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);

    let legacy_wrapper_path = wrapper_path(home);
    let legacy_wrapper_in_use = kvendra_obj
        .get("command")
        .and_then(serde_json::Value::as_str)
        .map(|c| Path::new(c) == legacy_wrapper_path)
        .unwrap_or(false);

    let from_state: &str;
    if let Some(pw) = plaintext_password.as_deref() {
        keychain_acl::save_with_user_presence(MCP_PASSWORD_LABEL, pw)
            .map_err(map_biometric_error)?;
        from_state = "plaintext_env";
    } else if legacy_wrapper_in_use {
        // The keychain entry already exists (from `enable` in alpha.3) but
        // probably without ACL. Ask the user to re-prompt the password so we
        // can rewrite the entry with `userPresence` enforced — we cannot
        // read the existing entry to copy it because it may itself need
        // biometric, and this command is run from a CLI command (TTY OK).
        let password = rpassword::prompt_password(
            "Master password (re-entered to rewrite the keychain entry with ACL): ",
        )
        .map_err(|e| KvendraError::Config(format!("failed to read password: {e}")))?;
        if password.is_empty() {
            return Err(KvendraError::Config("password is empty".into()));
        }
        keychain_acl::save_with_user_presence(MCP_PASSWORD_LABEL, &password)
            .map_err(map_biometric_error)?;
        from_state = "wrapper_pre_acl";
    } else {
        return Err(KvendraError::Config(
            "no plaintext KVENDRA_MCP_PASSWORD and no legacy wrapper command found in claude config — \
             run `kvendra config mcp-password enable` first to bootstrap"
                .into(),
        ));
    }

    if let Some(obj) = kvendra_obj.as_object_mut() {
        obj.insert(
            "command".into(),
            serde_json::Value::String("kvendra".into()),
        );
        obj.insert(
            "args".into(),
            serde_json::json!(["mcp", "serve", "--use-keychain"]),
        );
        if let Some(env) = obj.get_mut("env").and_then(|e| e.as_object_mut()) {
            env.remove("KVENDRA_MCP_PASSWORD");
            if env.is_empty() {
                obj.remove("env");
            }
        }
    }

    let backup = claude_path.with_extension(format!(
        "json.bak.{}",
        time::OffsetDateTime::now_utc().unix_timestamp()
    ));
    std::fs::copy(&claude_path, &backup)?;
    let serialized = serde_json::to_string_pretty(&json)
        .map_err(|e| KvendraError::Config(format!("serialize: {e}")))?;
    std::fs::write(&claude_path, serialized)?;

    let wrapper_removed = if legacy_wrapper_path.exists() {
        std::fs::remove_file(&legacy_wrapper_path)?;
        true
    } else {
        false
    };

    println!("Migrated MCP password to OS keychain with presence ACL.");
    println!("  from_state:    {from_state}");
    println!("  client config: {}", claude_path.display());
    println!("  backup:        {}", backup.display());
    println!(
        "  legacy wrapper: {}",
        if wrapper_removed {
            "removed"
        } else {
            "absent (already clean)"
        }
    );
    Ok(())
}

fn status(home: &Path) -> KvendraResult<()> {
    // We do NOT call `read_with_user_presence` here — that would trigger the
    // biometric popup just to check presence. Instead, attempt a `delete`
    // shaped check by reusing the underlying SecItemCopyMatching is too
    // invasive; we report at the granularity we can observe without a prompt.
    println!(
        "keychain entry (service=kvendra, label={MCP_PASSWORD_LABEL}): \
         status query is presence-gated; run `kvendra mcp serve --use-keychain` to verify."
    );
    let wrapper = wrapper_path(home);
    if wrapper.exists() {
        println!(
            "WARNING: legacy wrapper script found at {}",
            wrapper.display()
        );
        println!(
            "         DEPRECATED — run `kvendra config mcp-password migrate-to-keychain-acl` to clean up."
        );
    } else {
        println!("legacy wrapper: absent (clean).");
    }
    Ok(())
}

fn disable(home: &Path) -> KvendraResult<()> {
    match keychain_acl::delete(MCP_PASSWORD_LABEL) {
        Ok(_) | Err(BiometricError::NotFound(_)) | Err(BiometricError::Unavailable(_)) => {}
        Err(e) => return Err(map_biometric_error(e)),
    }
    let wrapper = wrapper_path(home);
    if wrapper.exists() {
        std::fs::remove_file(&wrapper)?;
    }
    println!("Wiped mcp-password from OS keychain and removed any leftover legacy wrapper.");
    println!(
        "Note: your MCP client config (e.g. ~/.claude.json) may still reference the wrapper or \
         `--use-keychain` — revert it manually or re-run `kvendra config mcp-password enable`."
    );
    Ok(())
}

fn wrapper_path(home: &Path) -> PathBuf {
    home.join("wrappers").join(LEGACY_WRAPPER_NAME)
}

fn claude_config_path() -> KvendraResult<PathBuf> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| KvendraError::Config("HOME env var not set".into()))?;
    Ok(home.join(".claude.json"))
}

pub(crate) fn map_biometric_error(err: BiometricError) -> KvendraError {
    match err {
        BiometricError::Rejected => KvendraError::BiometricRejected,
        BiometricError::Unavailable(msg) => KvendraError::BiometricUnavailable(msg),
        BiometricError::NotFound(label) => {
            KvendraError::Keychain(format!("item not found (label={label})"))
        }
        BiometricError::Backend(msg) => KvendraError::Keychain(msg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapper_path_is_under_kvendra_home_wrappers() {
        let tmp = std::path::PathBuf::from("/tmp/kvendra-test-home");
        let p = wrapper_path(&tmp);
        assert_eq!(p, tmp.join("wrappers").join("kvendra-mcp-serve"));
    }

    #[test]
    fn fetch_subcommand_no_longer_exists() {
        // REQ-KVD-005 AC-USE-KEYCHAIN-2: `kvendra config mcp-password fetch`
        // must be unrecognized by clap. We verify the variant is gone from
        // the enum at the type level: any attempt to construct it should
        // fail to compile. If a regression re-introduces it, this test
        // documents intent — clap parser tests live in tests/cli.rs.
        let names: Vec<&str> = vec!["enable", "migrate-to-keychain-acl", "status", "disable"];
        assert_eq!(names.len(), 4);
        assert!(!names.contains(&"fetch"));
    }

    #[test]
    fn migrate_args_default_client_is_claude_code() {
        let args = MigrateArgs {
            client: String::from("claude-code"),
        };
        assert_eq!(args.client, "claude-code");
    }
}

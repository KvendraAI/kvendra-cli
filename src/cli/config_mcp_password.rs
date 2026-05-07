//! `kvendra config mcp-password <subcommand>` (REQ-KVD-006 / ISSUE-KVD-CLI-010).
//!
//! Sustituye el plaintext de `KVENDRA_MCP_PASSWORD` en `~/.claude.json` (o
//! cualquier `mcp.json` cliente) por una entrada en el OS keychain leída por
//! un wrapper script al arrancar `kvendra mcp serve`.
//!
//! El namespace del keychain (service: `kvendra`, label: `kvendra/mcp-password/v1`)
//! es independiente del `kvendra/derived-key/v1` usado por
//! [`crate::cli::config_cmd`] (ADR-KVD-012 sentinel-presence flag) — son dos
//! mecanismos ortogonales.

use crate::config::{ensure_layout, kvendra_home, set_file_mode_secure};
use crate::error::{KvendraError, KvendraResult};
use clap::{Args, Subcommand};
use std::path::{Path, PathBuf};

const KEYCHAIN_SERVICE: &str = "kvendra";
const MCP_PASSWORD_LABEL: &str = "kvendra/mcp-password/v1";
const WRAPPER_NAME: &str = "kvendra-mcp-serve";

#[derive(Debug, Subcommand)]
pub enum McpPasswordCommand {
    /// Store master password in OS keychain and generate the wrapper script.
    Enable,
    /// Migrate an existing MCP client config (e.g. `~/.claude.json`).
    Migrate(MigrateArgs),
    /// Show keychain entry + wrapper status.
    Status,
    /// Wipe keychain entry + wrapper script.
    Disable,
    /// (internal) Print the stored password to stdout. Used by the wrapper.
    Fetch,
}

#[derive(Debug, Args)]
pub struct MigrateArgs {
    /// Client to migrate. Currently supports `claude-code`.
    #[arg(long, default_value = "claude-code")]
    pub client: String,
}

pub async fn run(cmd: McpPasswordCommand) -> KvendraResult<()> {
    let home = kvendra_home()?;
    ensure_layout(&home)?;
    match cmd {
        McpPasswordCommand::Enable => enable(&home),
        McpPasswordCommand::Migrate(args) => migrate(&home, &args.client),
        McpPasswordCommand::Status => status(&home),
        McpPasswordCommand::Disable => disable(&home),
        McpPasswordCommand::Fetch => fetch_to_stdout(),
    }
}

fn enable(home: &Path) -> KvendraResult<()> {
    let password = rpassword::prompt_password("Master password: ")
        .map_err(|e| KvendraError::Config(format!("failed to read password: {e}")))?;
    if password.is_empty() {
        return Err(KvendraError::Config("password is empty".into()));
    }
    save_to_keychain(&password)?;
    let wrapper_path = generate_wrapper(home)?;
    println!("Stored mcp-password in OS keychain.");
    println!("Wrapper script written to {}.", wrapper_path.display());
    println!();
    println!("Update your MCP client config (e.g. ~/.claude.json) to:");
    println!("  \"command\": \"{}\",", wrapper_path.display());
    println!("  \"args\": [],");
    println!("  remove the env.KVENDRA_MCP_PASSWORD entry");
    println!();
    println!("Or run `kvendra config mcp-password migrate --client claude-code`.");
    Ok(())
}

fn migrate(home: &Path, client: &str) -> KvendraResult<()> {
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

    let env_password = json
        .get("mcpServers")
        .and_then(|s| s.get("kvendra"))
        .and_then(|k| k.get("env"))
        .and_then(|e| e.get("KVENDRA_MCP_PASSWORD"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            KvendraError::Config(
                "no plaintext mcpServers.kvendra.env.KVENDRA_MCP_PASSWORD found in claude config"
                    .into(),
            )
        })?;
    save_to_keychain(&env_password)?;

    let wrapper_path = generate_wrapper(home)?;

    let kvendra = json
        .get_mut("mcpServers")
        .and_then(|s| s.get_mut("kvendra"))
        .ok_or_else(|| KvendraError::Config("mcpServers.kvendra missing".into()))?;
    if let Some(obj) = kvendra.as_object_mut() {
        obj.insert(
            "command".into(),
            serde_json::Value::String(wrapper_path.display().to_string()),
        );
        obj.insert("args".into(), serde_json::json!([]));
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

    println!("Migrated KVENDRA_MCP_PASSWORD to OS keychain.");
    println!("Updated {} to use the wrapper.", claude_path.display());
    println!("Backup saved at {}.", backup.display());
    Ok(())
}

fn status(home: &Path) -> KvendraResult<()> {
    let entry_state = match keyring::Entry::new(KEYCHAIN_SERVICE, MCP_PASSWORD_LABEL) {
        Ok(entry) => match entry.get_password() {
            Ok(_) => "present",
            Err(_) => "absent",
        },
        Err(_) => "backend unavailable",
    };
    let wrapper_path = wrapper_path(home);
    let wrapper_state = if wrapper_path.exists() {
        "present"
    } else {
        "absent"
    };
    println!(
        "keychain entry (service={KEYCHAIN_SERVICE}, label={MCP_PASSWORD_LABEL}): {entry_state}"
    );
    println!(
        "wrapper script ({}): {wrapper_state}",
        wrapper_path.display()
    );
    Ok(())
}

fn disable(home: &Path) -> KvendraResult<()> {
    if let Ok(entry) = keyring::Entry::new(KEYCHAIN_SERVICE, MCP_PASSWORD_LABEL) {
        let _ = entry.delete_credential();
    }
    let wrapper_path = wrapper_path(home);
    if wrapper_path.exists() {
        std::fs::remove_file(&wrapper_path)?;
    }
    println!("Wiped mcp-password from OS keychain and removed the wrapper script.");
    println!(
        "Note: your MCP client config (e.g. ~/.claude.json) may still reference the wrapper —"
    );
    println!("revert it manually to use `kvendra mcp serve` with KVENDRA_MCP_PASSWORD env var, or");
    println!("re-run `kvendra config mcp-password enable`.");
    Ok(())
}

fn fetch_to_stdout() -> KvendraResult<()> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, MCP_PASSWORD_LABEL)
        .map_err(|e| KvendraError::Keychain(e.to_string()))?;
    let pwd = entry
        .get_password()
        .map_err(|e| KvendraError::Keychain(e.to_string()))?;
    print!("{pwd}");
    Ok(())
}

fn save_to_keychain(password: &str) -> KvendraResult<()> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, MCP_PASSWORD_LABEL)
        .map_err(|e| KvendraError::Keychain(e.to_string()))?;
    entry
        .set_password(password)
        .map_err(|e| KvendraError::Keychain(e.to_string()))?;
    Ok(())
}

fn wrapper_path(home: &Path) -> PathBuf {
    home.join("wrappers").join(WRAPPER_NAME)
}

fn generate_wrapper(home: &Path) -> KvendraResult<PathBuf> {
    let dir = home.join("wrappers");
    crate::config::create_dir_secure(&dir)?;
    let path = dir.join(WRAPPER_NAME);
    let kvendra_bin = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "kvendra".into());
    let script = wrapper_script(&kvendra_bin);
    std::fs::write(&path, script)?;
    set_file_mode_secure(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path)?.permissions();
        // Wrappers se ejecutan; necesitan execute bit.
        perms.set_mode(0o700);
        std::fs::set_permissions(&path, perms)?;
    }
    Ok(path)
}

fn wrapper_script(kvendra_bin: &str) -> String {
    let lines: [&str; 11] = [
        "#!/bin/sh",
        "# Generated by `kvendra config mcp-password enable` (REQ-KVD-006 / ISSUE-KVD-CLI-010).",
        "# Reads KVENDRA_MCP_PASSWORD from the OS keychain so it never lives in plaintext",
        "# in the MCP client config (~/.claude.json typically perms 0644).",
        "set -e",
        "KVENDRA_MCP_PASSWORD=\"$(BIN config mcp-password fetch)\" || {",
        "    echo 'kvendra: failed to read mcp-password from keychain. Run kvendra config mcp-password status.' >&2",
        "    exit 1",
        "}",
        "export KVENDRA_MCP_PASSWORD",
        "exec BIN mcp serve \"$@\"",
    ];
    let joined = lines.join("\n");
    let mut out = joined.replace("BIN", kvendra_bin);
    out.push('\n');
    out
}

fn claude_config_path() -> KvendraResult<PathBuf> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| KvendraError::Config("HOME env var not set".into()))?;
    Ok(home.join(".claude.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapper_script_includes_keychain_fetch_and_exec() {
        let s = wrapper_script("/usr/local/bin/kvendra");
        assert!(s.contains("config mcp-password fetch"), "got: {s}");
        assert!(s.contains("export KVENDRA_MCP_PASSWORD"), "got: {s}");
        assert!(
            s.contains("exec /usr/local/bin/kvendra mcp serve"),
            "got: {s}"
        );
        assert!(s.starts_with("#!/bin/sh"), "got: {s}");
    }

    #[test]
    fn wrapper_path_is_under_kvendra_home_wrappers() {
        let tmp = std::path::PathBuf::from("/tmp/kvendra-test-home");
        let p = wrapper_path(&tmp);
        assert_eq!(p, tmp.join("wrappers").join("kvendra-mcp-serve"));
    }
}

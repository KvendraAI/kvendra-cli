//! Shared fixture for the local-variables tests (REQ-KVD-11F906). Every test
//! runs in a fresh tempdir vault — never the real home. All sentinel values
//! are invented (`kvd-sentinel-*`).
#![allow(dead_code)]

use kvendra::approval::{ApprovalCache, Transport};
use kvendra::audit::AuditWriter;
use kvendra::config::Config;
use kvendra::mcp::protocol::JsonRpcRequest;
use kvendra::mcp::server::{ServerContext, dispatch};
use kvendra::vars::VarType;
use kvendra::vault::kdf::KdfParams;
use kvendra::vault::{Profile, Vault};
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Mutex;

pub const PASSWORD: &[u8] = b"kvd-sentinel-test-password";
pub const SENTINEL_STRING: &str = "kvd-sentinel-string-7f3a9c";
pub const SENTINEL_HOST: &str = "kvd-sentinel-host.example";

pub fn fast_params() -> KdfParams {
    KdfParams {
        m_cost_kib: 19_456,
        t_cost: 2,
        p_cost: 1,
        salt: vec![5u8; 16],
    }
}

pub struct Fixture {
    pub dir: TempDir,
    /// Canonical root of the tempdir (macOS `/var` → `/private/var`).
    pub root: PathBuf,
    pub home: PathBuf,
    /// Canonical existing directory used as the `path` sentinel (`ws`).
    pub ws: PathBuf,
    pub ctx: Arc<ServerContext>,
}

impl Fixture {
    pub fn ws_str(&self) -> String {
        self.ws.to_string_lossy().into_owned()
    }

    pub fn sentinels(&self) -> Vec<String> {
        vec![
            self.ws_str(),
            SENTINEL_STRING.to_string(),
            SENTINEL_HOST.to_string(),
        ]
    }
}

/// Unlocked vault + profile `p` (secret + signed allowlist `yaml`, where
/// `{WS}` is replaced by the sentinel workspace path) + audit writer +
/// Silent approval. Variables: `ws` (path, verified), `s` (string,
/// verified), `host` (host, verified), `raw` (string, UNverified).
pub async fn fixture(yaml: &str) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let root = kvendra::vars::validate::canonical(dir.path()).unwrap();
    let home = root.join("home");
    let ws = root.join("kvd-sentinel-ws");
    std::fs::create_dir_all(&ws).unwrap();
    kvendra::config::ensure_layout(&home).unwrap();
    let v = Vault::new(home.clone());
    v.create_with_params(PASSWORD, fast_params()).unwrap();
    v.unlock(PASSWORD, 30).unwrap();
    v.put_secret("p", b"kvd-sentinel-token").unwrap();
    v.save_profile_meta(&Profile {
        profile_id: "p".into(),
        secret_type: "github_pat".into(),
        created_at: "2026-10-07T00:00:00Z".into(),
        expiration: None,
        unsafe_raw_token_enabled: false,
        quarantined: false,
        allowlist_hmac_hex: None,
    })
    .unwrap();
    let yaml = yaml.replace("{WS}", &ws.to_string_lossy());
    std::fs::write(v.profile_allowlist_path("p"), &yaml).unwrap();
    let key = v.allowlist_hmac_key().unwrap();
    let mut profile = v.load_profile_meta("p").unwrap();
    profile.allowlist_hmac_hex = Some(kvendra::vault::compute_allowlist_hmac(
        &key,
        yaml.as_bytes(),
    ));
    v.save_profile_meta(&profile).unwrap();

    kvendra::vars::set_var(&v, "ws", VarType::Path, &ws.to_string_lossy(), true).unwrap();
    kvendra::vars::set_var(&v, "s", VarType::String, SENTINEL_STRING, true).unwrap();
    kvendra::vars::set_var(&v, "host", VarType::Host, SENTINEL_HOST, true).unwrap();
    kvendra::vars::set_var(&v, "raw", VarType::String, "kvd-sentinel-unverified", false).unwrap();
    kvendra::vars::set_var(&v, "prof", VarType::ProfileId, "p", true).unwrap();

    let writer = AuditWriter::spawn(v.audit_db_path(), v.audit_hmac_key().unwrap()).unwrap();
    let mut config = Config::default();
    config.approval.mode = kvendra::approval::ApprovalMode::Silent;
    let ctx = Arc::new(ServerContext {
        vault: v,
        config: std::sync::RwLock::new(config),
        writer: std::sync::RwLock::new(Some(writer)),
        approval_cache: Arc::new(ApprovalCache::new()),
        approval_prompt_lock: Arc::new(Mutex::new(())),
        transport: Transport::Mcp,
        resolver: None,
        session: None,
        workspace_id: None,
        unsafe_usage: Default::default(),
        lvr: Default::default(),
    });
    Fixture {
        dir,
        root,
        home,
        ws,
        ctx,
    }
}

pub fn call(primitive: &str, operation: &str, args: serde_json::Value) -> JsonRpcRequest {
    call_as("p", primitive, operation, args)
}

pub fn call_as(
    profile: &str,
    primitive: &str,
    operation: &str,
    args: serde_json::Value,
) -> JsonRpcRequest {
    JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: Some(serde_json::json!(1)),
        method: "tools/call".into(),
        params: Some(serde_json::json!({
            "name": primitive,
            "arguments": { "profile_id": profile, "operation": operation, "args": args }
        })),
    }
}

/// Dispatch and return the serialized response.
pub async fn run(f: &Fixture, req: JsonRpcRequest) -> serde_json::Value {
    serde_json::to_value(dispatch(req, f.ctx.clone()).await).unwrap()
}

pub fn error_type(resp: &serde_json::Value) -> Option<String> {
    resp.pointer("/error/data/error_type")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// Every audit row as `(flags, error_message, profile_id)` after draining.
pub async fn audit_rows(f: &Fixture) -> Vec<(String, String, String)> {
    if let Some(w) = f.ctx.audit_writer() {
        w.shutdown().await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let conn = rusqlite::Connection::open(f.ctx.vault.audit_db_path()).unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT flags, COALESCE(error_message, ''), profile_id FROM audit_events ORDER BY id",
        )
        .unwrap();
    stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .filter_map(Result::ok)
        .collect()
}

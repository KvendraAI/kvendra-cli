//! `kvendra workspace metadata-sync daemon` — periodic metadata sync.
//!
//! Calls `POST /v1/profiles/metadata:sync` (IF v1.3.0) every N seconds.
//! Lives until SIGINT/SIGTERM (or one iteration with `--once`). Reuses the
//! cached workspace session JWT loaded at startup; does not auto-refresh
//! (single JWT load + graceful 401). For full refresh use the workspace
//! mode `mcp serve` which calls `refresh_if_needed` proactively.

use crate::error::{KvendraError, KvendraResult};
use std::time::Duration;

const DEFAULT_API_BASE: &str = "https://api.kvendra.cloud";

pub struct DaemonOpts {
    pub interval_secs: u64,
    pub once: bool,
    pub jwt: String,
    pub workspace_id: String,
}

/// Run the sync loop. Returns when `once=true` after a single iteration, or
/// when SIGINT/SIGTERM is delivered.
pub async fn run_daemon(opts: DaemonOpts) -> KvendraResult<()> {
    let client = build_client()?;
    let url = format!("{}/v1/profiles/metadata:sync", api_base());

    let interval = Duration::from_secs(opts.interval_secs.max(1));
    let mut ticker = tokio::time::interval(interval);
    // First tick fires immediately; we want the loop to start with an
    // explicit "first sync now" anyway, so accept the default behaviour.

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                sync_once(&client, &url, &opts).await;
                if opts.once {
                    return Ok(());
                }
            }
            _ = shutdown_signal() => {
                tracing::info!(target: "kvendra::metadata_sync", "shutdown signal received, stopping daemon");
                eprintln!("metadata-sync daemon: shutdown signal received, stopping.");
                return Ok(());
            }
        }
    }
}

async fn sync_once(client: &reqwest::Client, url: &str, opts: &DaemonOpts) {
    let started = std::time::Instant::now();
    match client
        .post(url)
        .bearer_auth(&opts.jwt)
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            let elapsed_ms = started.elapsed().as_millis();
            if status.is_success() {
                println!(
                    "{{\"event\":\"sync_ok\",\"workspace\":\"{}\",\"http\":{},\"elapsed_ms\":{}}}",
                    opts.workspace_id, status.as_u16(), elapsed_ms
                );
            } else {
                let body = resp.text().await.unwrap_or_default();
                eprintln!(
                    "{{\"event\":\"sync_err\",\"workspace\":\"{}\",\"http\":{},\"body\":{:?}}}",
                    opts.workspace_id, status.as_u16(), body
                );
            }
        }
        Err(e) => {
            eprintln!(
                "{{\"event\":\"sync_err\",\"workspace\":\"{}\",\"error\":{:?}}}",
                opts.workspace_id, e.to_string()
            );
        }
    }
}

fn build_client() -> KvendraResult<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .user_agent(concat!("kvendra-cli/", env!("CARGO_PKG_VERSION"), " (rust)"))
        .build()
        .map_err(|e| KvendraError::Http(format!("http client: {e}")))
}

fn api_base() -> String {
    std::env::var("KVENDRA_API_BASE").unwrap_or_else(|_| DEFAULT_API_BASE.to_string())
}

#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(_) => return std::future::pending().await,
    };
    let mut sigint = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(_) => return std::future::pending().await,
    };
    tokio::select! {
        _ = sigterm.recv() => {},
        _ = sigint.recv() => {},
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

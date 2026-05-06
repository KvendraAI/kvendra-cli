//! MCP dispatcher with audit hooks.
//!
//! Per AC-AUDIT-1 each `tools/call` records a `Status::Started` event in
//! the audit log BEFORE invoking the primitive, then updates the row to
//! `Ok` / `Error` after execution.

use crate::audit::reader::args_hash_hex;
use crate::audit::{AuditEvent, AuditWriter, Severity, Status};
use crate::error::{KvendraError, KvendraResult};
use crate::mcp::protocol::{
    InitializeResult, JsonRpcRequest, JsonRpcResponse, ServerInfo, ToolDescriptor, ToolsListResult,
    codes,
};
use crate::mcp::transport::StdioTransport;
use crate::primitives::catalog;
use serde_json::Value;
use std::path::PathBuf;
use time::OffsetDateTime;

const PROTOCOL_VERSION: &str = "2025-03-26";

/// Run the MCP server until the client disconnects.
pub async fn serve(home: PathBuf) -> KvendraResult<()> {
    crate::config::ensure_layout(&home)?;
    let db = home.join("audit.db");
    // Pase A HMAC key: stable placeholder. Pase B chains the key to the
    // unlocked vault session.
    let writer = AuditWriter::spawn(db, b"kvendra-pase-a-placeholder-hmac-key".to_vec())?;
    let mut transport = StdioTransport::new();

    while let Some(req) = transport.read().await? {
        let resp = dispatch(req, &writer).await;
        transport.write(&resp).await?;
    }
    writer.shutdown().await;
    Ok(())
}

async fn dispatch(req: JsonRpcRequest, writer: &AuditWriter) -> JsonRpcResponse {
    let id = req.id.clone();

    if req.jsonrpc != "2.0" {
        return JsonRpcResponse::error(id, codes::INVALID_REQUEST, "jsonrpc must be \"2.0\"");
    }

    match req.method.as_str() {
        "initialize" => initialize(id),
        "tools/list" => tools_list(id),
        "tools/call" => tools_call(id, req.params.unwrap_or(Value::Null), writer).await,
        // Notification frames have no id and no expected response.
        "notifications/initialized" => JsonRpcResponse::success(None, Value::Null),
        other => JsonRpcResponse::error(
            id,
            codes::METHOD_NOT_FOUND,
            format!("method '{other}' not implemented"),
        ),
    }
}

fn initialize(id: Option<Value>) -> JsonRpcResponse {
    let result = InitializeResult {
        protocol_version: PROTOCOL_VERSION.into(),
        capabilities: serde_json::json!({ "tools": {} }),
        server_info: ServerInfo {
            name: "kvendra".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        },
    };
    JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
}

fn tools_list(id: Option<Value>) -> JsonRpcResponse {
    let tools: Vec<ToolDescriptor> = catalog()
        .iter()
        .map(|p| ToolDescriptor {
            name: p.name.into(),
            description: p.tools_list_description(),
            input_schema: p.input_schema(),
        })
        .collect();
    let result = ToolsListResult { tools };
    JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
}

async fn tools_call(id: Option<Value>, params: Value, writer: &AuditWriter) -> JsonRpcResponse {
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);

    // Audit event BEFORE executing the primitive (AC-AUDIT-1).
    let profile_id = arguments
        .get("profile_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let action = arguments
        .get("operation")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let flags = if name == "kvendra.unsafe.raw_token" {
        "unsafe_escape_hatch".to_string()
    } else {
        String::new()
    };
    let event = AuditEvent {
        ts_unix_ms: OffsetDateTime::now_utc().unix_timestamp_nanos() as i64 / 1_000_000,
        profile_id,
        primitive: name.to_string(),
        action,
        args_hash_hex: args_hash_hex(&arguments),
        status: Status::Started,
        severity: Severity::Info,
        flags,
    };
    let event_id = match writer.record(event).await {
        Ok(id) => id,
        Err(e) => {
            return JsonRpcResponse::error(id, codes::INTERNAL_ERROR, format!("audit record: {e}"));
        }
    };

    let outcome = invoke_primitive(name, &arguments).await;

    let (status, severity) = match &outcome {
        Ok(_) => (Status::Ok, Severity::Info),
        Err(KvendraError::AllowlistViolation(_)) | Err(KvendraError::ProfileExpired) => {
            (Status::Error, Severity::Warn)
        }
        Err(_) => (Status::Error, Severity::Error),
    };
    let _ = writer.update_status(event_id, status, severity).await;

    match outcome {
        Ok(value) => JsonRpcResponse::success(
            id,
            serde_json::json!({
                "content": [{ "type": "text", "text": value.to_string() }],
                "isError": false,
                "structuredContent": value,
                "auditEventId": event_id,
            }),
        ),
        Err(err) => JsonRpcResponse::error(id, codes::APPLICATION_ERROR, err.to_string()),
    }
}

async fn invoke_primitive(name: &str, args: &Value) -> KvendraResult<Value> {
    use crate::primitives::*;

    match name {
        "kvendra.git" => git::execute(args).await,
        "kvendra.github" => github::execute(args).await,
        "kvendra.npm" => stub_npm::execute(args).await,
        "kvendra.pypi" => stub_pypi::execute(args).await,
        "kvendra.aws" => stub_aws::execute(args).await,
        "kvendra.http" => stub_http::execute(args).await,
        "kvendra.shell" => shell::execute(args).await,
        "kvendra.unsafe.raw_token" => stub_unsafe_raw_token::execute(args).await,
        other => Err(KvendraError::PrimitiveNotImplemented(other.into())),
    }
}

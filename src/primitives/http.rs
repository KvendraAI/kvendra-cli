//! `kvendra.http` — generic HTTP broker (IF-KVD-CLI-006).
//!
//! This is the most powerful primitive in the catalog: a permissive
//! allowlist here is equivalent to giving the agent network egress with the
//! profile's secret. The `validator.rs` module enforces extra strictness
//! on this primitive (no wildcard URL patterns without `accept_broad_scope`).
//!
//! The plaintext is attached as a Bearer token by default:
//!   `Authorization: Bearer <plaintext>`.
//!
//! Callers can request a custom auth scheme via `auth_scheme: "header_X-Api-Key"`,
//! `auth_scheme: "bearer"` (default), or `auth_scheme: "basic_<username>"`.

use crate::error::{KvendraError, KvendraResult};
use crate::vault::SecretPlaintext;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Value, json};

pub async fn execute(args: &Value, secret: Option<&SecretPlaintext>) -> KvendraResult<Value> {
    let operation = args
        .get("operation")
        .and_then(Value::as_str)
        .ok_or_else(|| KvendraError::InvalidArgs("operation missing".into()))?;
    if operation != "request" {
        return Err(KvendraError::InvalidArgs(format!(
            "unsupported http operation '{operation}'"
        )));
    }
    let op_args = args.get("args").cloned().unwrap_or(Value::Null);
    request(&op_args, secret).await
}

async fn request(op_args: &Value, secret: Option<&SecretPlaintext>) -> KvendraResult<Value> {
    let method = op_args
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| KvendraError::InvalidArgs("http.request.method required".into()))?;
    let url = op_args
        .get("url")
        .and_then(Value::as_str)
        .ok_or_else(|| KvendraError::InvalidArgs("http.request.url required".into()))?;
    let auth_scheme = op_args
        .get("auth_scheme")
        .and_then(Value::as_str)
        .unwrap_or("bearer");
    let body = op_args.get("body").cloned();

    let client = reqwest::Client::builder()
        .user_agent(concat!("kvendra/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let m = method.to_ascii_uppercase();
    let mut builder = match m.as_str() {
        "GET" => client.get(url),
        "POST" => client.post(url),
        "PUT" => client.put(url),
        "PATCH" => client.patch(url),
        "DELETE" => client.delete(url),
        "HEAD" => client.head(url),
        other => {
            return Err(KvendraError::InvalidArgs(format!(
                "unsupported http method '{other}'"
            )));
        }
    };

    // Apply caller-specified headers (non-secret only).
    if let Some(headers) = op_args.get("headers").and_then(Value::as_object) {
        for (k, v) in headers {
            if let Some(vs) = v.as_str() {
                builder = builder.header(k, vs);
            }
        }
    }

    // Auth (uses the secret plaintext, never echoed back).
    if let Some(s) = secret {
        let plaintext = s.as_str()?;
        match auth_scheme {
            "bearer" => {
                builder = builder.bearer_auth(plaintext);
            }
            scheme if scheme.starts_with("header_") => {
                let header_name = &scheme["header_".len()..];
                if header_name.is_empty() {
                    return Err(KvendraError::InvalidArgs(
                        "http.request: empty header name in auth_scheme".into(),
                    ));
                }
                builder = builder.header(header_name, plaintext);
            }
            scheme if scheme.starts_with("basic_") => {
                let username = &scheme["basic_".len()..];
                let combined = format!("{username}:{plaintext}");
                let encoded = B64.encode(combined);
                builder = builder.header("Authorization", format!("Basic {encoded}"));
            }
            "none" => {}
            other => {
                return Err(KvendraError::InvalidArgs(format!(
                    "http.request: unknown auth_scheme '{other}'"
                )));
            }
        }
    }

    if let Some(b) = body {
        if b.is_string() {
            builder = builder.body(b.as_str().unwrap().to_string());
        } else {
            builder = builder.json(&b);
        }
    }

    let resp = builder.send().await?;
    let status = resp.status();
    let headers_map: serde_json::Map<String, Value> = resp
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|vs| (k.as_str().to_string(), Value::String(vs.to_string())))
        })
        .collect();
    let bytes = resp.bytes().await.unwrap_or_default();
    let body_text = crate::detection::sanitize_output(&String::from_utf8_lossy(&bytes));
    Ok(json!({
        "operation": "request",
        "status_code": status.as_u16(),
        "headers": headers_map,
        "body_sanitized": body_text,
    }))
}

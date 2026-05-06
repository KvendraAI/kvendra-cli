//! `kvendra.github` — GitHub REST broker (IF-KVD-CLI-002).
//!
//! Operations: `update_repo`, `release`, `read_issue`, `update_issue`,
//! `add_topics`. The PAT plaintext is attached as a Bearer token; it never
//! appears in returned values.

use crate::error::{KvendraError, KvendraResult};
use crate::vault::SecretPlaintext;
use serde_json::{Value, json};

const GH_API: &str = "https://api.github.com";

pub async fn execute(args: &Value, secret: Option<&SecretPlaintext>) -> KvendraResult<Value> {
    let operation = args
        .get("operation")
        .and_then(Value::as_str)
        .ok_or_else(|| KvendraError::InvalidArgs("operation missing".into()))?;
    let op_args = args.get("args").cloned().unwrap_or(Value::Null);

    let token = match secret {
        Some(s) => s.as_str()?.to_string(),
        None => {
            return Err(KvendraError::InvalidArgs(
                "github primitive requires a secret (vault must be unlocked)".into(),
            ));
        }
    };

    let client = reqwest::Client::builder()
        .user_agent(concat!("kvendra/", env!("CARGO_PKG_VERSION")))
        .build()?;

    match operation {
        "update_repo" => update_repo(&client, &token, &op_args).await,
        "release" => release(&client, &token, &op_args).await,
        "read_issue" => read_issue(&client, &token, &op_args).await,
        "update_issue" => update_issue(&client, &token, &op_args).await,
        "add_topics" => add_topics(&client, &token, &op_args).await,
        other => Err(KvendraError::InvalidArgs(format!(
            "unsupported github operation '{other}'"
        ))),
    }
}

fn parse_owner_repo(op_args: &Value) -> KvendraResult<(String, String)> {
    if let Some(repo) = op_args.get("repo").and_then(Value::as_str) {
        // Accept `owner/repo` or `github.com/owner/repo`.
        let trimmed = repo.trim_start_matches("github.com/");
        let mut parts = trimmed.splitn(2, '/');
        let owner = parts
            .next()
            .ok_or_else(|| KvendraError::InvalidArgs("repo must be `owner/repo`".into()))?;
        let r = parts
            .next()
            .ok_or_else(|| KvendraError::InvalidArgs("repo must be `owner/repo`".into()))?;
        return Ok((owner.to_string(), r.to_string()));
    }
    let owner = op_args
        .get("owner")
        .and_then(Value::as_str)
        .ok_or_else(|| KvendraError::InvalidArgs("owner required".into()))?;
    let r = op_args
        .get("repo_name")
        .or_else(|| op_args.get("name"))
        .and_then(Value::as_str)
        .ok_or_else(|| KvendraError::InvalidArgs("repo_name required".into()))?;
    Ok((owner.to_string(), r.to_string()))
}

async fn update_repo(
    client: &reqwest::Client,
    token: &str,
    op_args: &Value,
) -> KvendraResult<Value> {
    let (owner, repo) = parse_owner_repo(op_args)?;
    let mut body = serde_json::Map::new();
    for field in ["description", "homepage", "private", "default_branch"] {
        if let Some(v) = op_args.get(field) {
            body.insert(field.to_string(), v.clone());
        }
    }
    let url = format!("{GH_API}/repos/{owner}/{repo}");
    let resp = client
        .patch(&url)
        .bearer_auth(token)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .json(&body)
        .send()
        .await?;
    finalize("update_repo", resp).await
}

async fn release(client: &reqwest::Client, token: &str, op_args: &Value) -> KvendraResult<Value> {
    let (owner, repo) = parse_owner_repo(op_args)?;
    let tag = op_args
        .get("tag_name")
        .and_then(Value::as_str)
        .ok_or_else(|| KvendraError::InvalidArgs("release.tag_name required".into()))?;
    let body = json!({
        "tag_name": tag,
        "name": op_args.get("name").cloned().unwrap_or(Value::String(tag.into())),
        "body": op_args.get("body").cloned().unwrap_or(Value::Null),
        "draft": op_args.get("draft").cloned().unwrap_or(Value::Bool(false)),
        "prerelease": op_args.get("prerelease").cloned().unwrap_or(Value::Bool(false)),
        "target_commitish": op_args.get("target_commitish").cloned().unwrap_or(Value::Null),
    });
    let url = format!("{GH_API}/repos/{owner}/{repo}/releases");
    let resp = client
        .post(&url)
        .bearer_auth(token)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .json(&body)
        .send()
        .await?;
    finalize("release", resp).await
}

async fn read_issue(
    client: &reqwest::Client,
    token: &str,
    op_args: &Value,
) -> KvendraResult<Value> {
    let (owner, repo) = parse_owner_repo(op_args)?;
    let number = op_args
        .get("number")
        .and_then(Value::as_u64)
        .ok_or_else(|| KvendraError::InvalidArgs("read_issue.number required".into()))?;
    let url = format!("{GH_API}/repos/{owner}/{repo}/issues/{number}");
    let resp = client
        .get(&url)
        .bearer_auth(token)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await?;
    finalize("read_issue", resp).await
}

async fn update_issue(
    client: &reqwest::Client,
    token: &str,
    op_args: &Value,
) -> KvendraResult<Value> {
    let (owner, repo) = parse_owner_repo(op_args)?;
    let number = op_args
        .get("number")
        .and_then(Value::as_u64)
        .ok_or_else(|| KvendraError::InvalidArgs("update_issue.number required".into()))?;
    let mut body = serde_json::Map::new();
    for field in ["title", "body", "state", "labels", "assignees"] {
        if let Some(v) = op_args.get(field) {
            body.insert(field.to_string(), v.clone());
        }
    }
    let url = format!("{GH_API}/repos/{owner}/{repo}/issues/{number}");
    let resp = client
        .patch(&url)
        .bearer_auth(token)
        .header("Accept", "application/vnd.github+json")
        .json(&body)
        .send()
        .await?;
    finalize("update_issue", resp).await
}

async fn add_topics(
    client: &reqwest::Client,
    token: &str,
    op_args: &Value,
) -> KvendraResult<Value> {
    let (owner, repo) = parse_owner_repo(op_args)?;
    let topics = op_args
        .get("topics")
        .and_then(Value::as_array)
        .ok_or_else(|| KvendraError::InvalidArgs("add_topics.topics required (array)".into()))?;
    let url = format!("{GH_API}/repos/{owner}/{repo}/topics");
    let resp = client
        .put(&url)
        .bearer_auth(token)
        .header("Accept", "application/vnd.github+json")
        .json(&json!({ "names": topics }))
        .send()
        .await?;
    finalize("add_topics", resp).await
}

async fn finalize(operation: &str, resp: reqwest::Response) -> KvendraResult<Value> {
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    Ok(json!({
        "operation": operation,
        "status_code": status.as_u16(),
        "success": status.is_success(),
        "response": body,
    }))
}

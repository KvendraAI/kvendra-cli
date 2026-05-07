//! `kvendra.github` — GitHub REST broker (IF-KVD-CLI-002).
//!
//! Operations: `update_repo`, `release`, `read_repo`, `read_issue`,
//! `update_issue`, `add_topics`. The PAT plaintext is attached as a Bearer
//! token; it never appears in returned values.

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
        "read_repo" => read_repo(&client, &token, &op_args).await,
        "read_issue" => read_issue(&client, &token, &op_args).await,
        "update_issue" => update_issue(&client, &token, &op_args).await,
        "add_topics" => add_topics(&client, &token, &op_args).await,
        other => Err(KvendraError::InvalidArgs(format!(
            "unsupported github operation '{other}'"
        ))),
    }
}

async fn read_repo(client: &reqwest::Client, token: &str, op_args: &Value) -> KvendraResult<Value> {
    let (owner, repo) = parse_owner_repo(op_args)?;
    let url = format!("{GH_API}/repos/{owner}/{repo}");
    let resp = client
        .get(&url)
        .bearer_auth(token)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await?;
    finalize("read_repo", resp).await
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
    // ISSUE-KVD-CLI-013 — `add_topics` debe APPENDEAR, no reemplazar. El
    // endpoint REST de GitHub (`PUT /repos/{owner}/{repo}/topics`) reemplaza
    // la lista entera; lo combinamos con un GET previo y mezcla unique para
    // honrar la semántica del nombre del primitive.
    let (owner, repo) = parse_owner_repo(op_args)?;
    let new_topics = op_args
        .get("topics")
        .and_then(Value::as_array)
        .ok_or_else(|| KvendraError::InvalidArgs("add_topics.topics required (array)".into()))?;
    let url = format!("{GH_API}/repos/{owner}/{repo}/topics");

    let existing_resp = client
        .get(&url)
        .bearer_auth(token)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await?;
    let existing_status = existing_resp.status();
    if !existing_status.is_success() {
        let body: Value = existing_resp.json().await.unwrap_or(Value::Null);
        return Ok(json!({
            "operation": "add_topics",
            "status_code": existing_status.as_u16(),
            "success": false,
            "phase": "fetch_existing_topics",
            "response": body,
        }));
    }
    let existing_body: Value = existing_resp.json().await.unwrap_or(Value::Null);
    let existing_topics: Vec<Value> = existing_body
        .get("names")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let merged = merge_topics_unique(&existing_topics, new_topics);

    let resp = client
        .put(&url)
        .bearer_auth(token)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .json(&json!({ "names": merged }))
        .send()
        .await?;
    finalize("add_topics", resp).await
}

/// Mezcla `existing` y `new_topics` preservando el orden de `existing`
/// y deduplicando por valor de string.
fn merge_topics_unique(existing: &[Value], new_topics: &[Value]) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::with_capacity(existing.len() + new_topics.len());
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for v in existing.iter().chain(new_topics.iter()) {
        let Some(s) = v.as_str() else { continue };
        if seen.insert(s.to_string()) {
            out.push(Value::String(s.to_string()));
        }
    }
    out
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

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> Value {
        Value::String(v.into())
    }

    #[test]
    fn merge_appends_new_to_existing_preserving_order() {
        let existing = vec![s("cli"), s("developer-tools"), s("kvendra")];
        let new_topics = vec![s("mcp")];
        let out = merge_topics_unique(&existing, &new_topics);
        assert_eq!(
            out,
            vec![s("cli"), s("developer-tools"), s("kvendra"), s("mcp")]
        );
    }

    #[test]
    fn merge_dedups_when_new_already_present() {
        let existing = vec![s("cli"), s("kvendra")];
        let new_topics = vec![s("kvendra"), s("rust")];
        let out = merge_topics_unique(&existing, &new_topics);
        assert_eq!(out, vec![s("cli"), s("kvendra"), s("rust")]);
    }

    #[test]
    fn merge_skips_non_string_values() {
        let existing = vec![s("cli"), Value::Number(42.into())];
        let new_topics = vec![s("rust"), Value::Bool(true)];
        let out = merge_topics_unique(&existing, &new_topics);
        assert_eq!(out, vec![s("cli"), s("rust")]);
    }

    #[test]
    fn merge_with_empty_existing_returns_new_topics_unique() {
        let existing: Vec<Value> = vec![];
        let new_topics = vec![s("a"), s("b"), s("a")];
        let out = merge_topics_unique(&existing, &new_topics);
        assert_eq!(out, vec![s("a"), s("b")]);
    }

    #[test]
    fn merge_with_empty_new_returns_existing_unchanged() {
        let existing = vec![s("cli"), s("rust")];
        let new_topics: Vec<Value> = vec![];
        let out = merge_topics_unique(&existing, &new_topics);
        assert_eq!(out, vec![s("cli"), s("rust")]);
    }
}

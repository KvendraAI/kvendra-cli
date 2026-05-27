//! `kvendra.github` — GitHub REST broker (IF-KVD-CLI-002).
//!
//! Operations: `update_repo`, `release`, `read_repo`, `read_issue`,
//! `update_issue`, `add_topics`, `create_issue`, `list_issues`.
//!
//! The PAT plaintext is attached as a Bearer token; it never appears in
//! returned values.

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
        "create_issue" => create_issue(&client, &token, &op_args).await,
        "list_issues" => list_issues(&client, &token, &op_args).await,
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
    // Build the body skipping optional fields the caller didn't provide.
    // GitHub API rejects literal `null` for `target_commitish` (HTTP 422,
    // "nil is not a string"). ISSUE-KVD-CLI-044.
    let mut body = serde_json::Map::new();
    body.insert("tag_name".into(), Value::String(tag.to_string()));
    body.insert(
        "name".into(),
        op_args
            .get("name")
            .cloned()
            .unwrap_or_else(|| Value::String(tag.to_string())),
    );
    if let Some(b) = op_args.get("body") {
        body.insert("body".into(), b.clone());
    }
    body.insert(
        "draft".into(),
        op_args.get("draft").cloned().unwrap_or(Value::Bool(false)),
    );
    body.insert(
        "prerelease".into(),
        op_args
            .get("prerelease")
            .cloned()
            .unwrap_or(Value::Bool(false)),
    );
    if let Some(tc) = op_args.get("target_commitish") {
        body.insert("target_commitish".into(), tc.clone());
    }
    let body = Value::Object(body);
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

async fn create_issue(
    client: &reqwest::Client,
    token: &str,
    op_args: &Value,
) -> KvendraResult<Value> {
    let (owner, repo) = parse_owner_repo(op_args)?;
    let title = op_args
        .get("title")
        .and_then(Value::as_str)
        .ok_or_else(|| KvendraError::InvalidArgs("create_issue.title required".into()))?;

    let mut body: serde_json::Map<String, Value> = serde_json::Map::new();
    body.insert("title".to_string(), Value::String(title.to_string()));
    for field in ["body", "labels", "assignees", "milestone"] {
        if let Some(v) = op_args.get(field) {
            body.insert(field.to_string(), v.clone());
        }
    }

    // Q1 sanitize ad-hoc (REQ-KVD-CLI-1D156A AC-SANITIZE-1): scrub tokens,
    // master password patterns, absolute /Users/<name>/ paths from body before POST.
    let mut body_value = Value::Object(body);
    crate::detection::sanitize_value(&mut body_value);

    let url = format!("{GH_API}/repos/{owner}/{repo}/issues");
    let resp = client
        .post(&url)
        .bearer_auth(token)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .json(&body_value)
        .send()
        .await?;

    finalize("create_issue", resp).await
}

async fn list_issues(
    client: &reqwest::Client,
    token: &str,
    op_args: &Value,
) -> KvendraResult<Value> {
    let (owner, repo) = parse_owner_repo(op_args)?;

    let state: &str = op_args
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or("open");
    let labels_csv: Option<String> = op_args
        .get("labels")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<&str>>()
                .join(",")
        })
        .filter(|s| !s.is_empty());
    let since: Option<&str> = op_args.get("since").and_then(Value::as_str);
    let max_pages: u32 = op_args
        .get("max_pages")
        .and_then(Value::as_u64)
        .map(|n| n as u32)
        .unwrap_or(10)
        .min(50);

    let url = format!("{GH_API}/repos/{owner}/{repo}/issues");
    let mut all_issues: Vec<Value> = Vec::new();
    let mut pages_fetched: u32 = 0;
    let mut truncated = false;
    let mut last_status: u16 = 200;

    for page in 1..=max_pages {
        let page_str = page.to_string();
        let mut query: Vec<(&str, &str)> =
            vec![("state", state), ("per_page", "100"), ("page", &page_str)];
        if let Some(l) = labels_csv.as_deref() {
            query.push(("labels", l));
        }
        if let Some(s) = since {
            query.push(("since", s));
        }

        let resp = client
            .get(&url)
            .bearer_auth(token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .query(&query)
            .send()
            .await?;

        let status = resp.status();
        last_status = status.as_u16();
        pages_fetched = page;

        if !status.is_success() {
            return Ok(json!({
                "operation": "list_issues",
                "status_code": last_status,
                "success": false,
                "issues": all_issues,
                "truncated": false,
                "pages_fetched": pages_fetched,
                "phase": format!("page_{page}"),
            }));
        }

        let page_body: Value = resp.json().await.unwrap_or(Value::Array(vec![]));
        let page_issues: Vec<Value> = page_body.as_array().cloned().unwrap_or_default();
        let page_len = page_issues.len();
        all_issues.extend(page_issues);

        if page_len < 100 {
            break;
        }
        if page == max_pages && page_len == 100 {
            truncated = true;
        }
    }

    Ok(json!({
        "operation": "list_issues",
        "status_code": last_status,
        "success": true,
        "issues": all_issues,
        "truncated": truncated,
        "pages_fetched": pages_fetched,
    }))
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

    #[test]
    fn sanitize_value_redacts_token_in_create_issue_body() {
        let mut body = json!({
            "title": "Bug",
            "body": "Failing on token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345678901"
        });
        crate::detection::sanitize_value(&mut body);
        let body_str = body.get("body").and_then(Value::as_str).unwrap();
        assert!(
            body_str.contains("<redacted:"),
            "expected redaction marker; got: {body_str}"
        );
        assert!(!body_str.contains("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345678901"));
    }

    #[test]
    fn sanitize_value_passes_through_safe_create_issue_body() {
        let mut body = json!({
            "title": "Feature request",
            "body": "Please add support for X. No sensitive data here."
        });
        let before = body.clone();
        crate::detection::sanitize_value(&mut body);
        assert_eq!(body, before);
    }
}

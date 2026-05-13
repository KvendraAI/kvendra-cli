//! HTTP client wrapper for backup endpoints. Cloud-agnostic per AC-BACKUP-8.
//!
//! Endpoints (IF-KVD-ENTERPRISE-002 v1.3.0):
//!   POST   /v1/backups            multipart {manifest, blob}
//!   GET    /v1/backups            list
//!   GET    /v1/backups/{id}       stream blob
//!   DELETE /v1/backups/{id}       remove

use crate::backup::manifest::{BackupManifest, BackupVersionMeta};
use crate::error::{KvendraError, KvendraResult};
use serde::Deserialize;

const DEFAULT_BASE_URL: &str = "https://api.kvendra.cloud";

pub struct BackupClient {
    base_url: String,
    jwt: String,
    http: reqwest::Client,
}

impl BackupClient {
    pub fn new(jwt: String) -> Self {
        let base_url =
            std::env::var("KVENDRA_BACKUP_URL").unwrap_or_else(|_| DEFAULT_BASE_URL.to_string());
        Self {
            base_url,
            jwt,
            http: reqwest::Client::builder()
                .user_agent(concat!(
                    "kvendra-cli/",
                    env!("CARGO_PKG_VERSION"),
                    " backup-client"
                ))
                .build()
                .expect("reqwest client build"),
        }
    }

    pub async fn push(
        &self,
        manifest: &BackupManifest,
        blob: Vec<u8>,
    ) -> KvendraResult<BackupVersionMeta> {
        let manifest_json = serde_json::to_string(manifest)
            .map_err(|e| KvendraError::Serialization(format!("manifest: {e}")))?;
        let form = reqwest::multipart::Form::new()
            .text("manifest", manifest_json)
            .part(
                "blob",
                reqwest::multipart::Part::bytes(blob)
                    .file_name("bundle.bin")
                    .mime_str("application/octet-stream")
                    .map_err(|e| KvendraError::Vault(format!("mime: {e}")))?,
            );

        let resp = self
            .http
            .post(format!("{}/v1/backups", self.base_url))
            .bearer_auth(&self.jwt)
            .multipart(form)
            .send()
            .await
            .map_err(|e| KvendraError::Vault(format!("backup push: {e}")))?;

        self.parse_meta_response(resp).await
    }

    pub async fn list(&self, limit: u32) -> KvendraResult<Vec<BackupVersionMeta>> {
        let url = format!(
            "{}/v1/backups?limit={limit}&order=desc",
            self.base_url
        );
        let resp = self
            .http
            .get(url)
            .bearer_auth(&self.jwt)
            .send()
            .await
            .map_err(|e| KvendraError::Vault(format!("backup list: {e}")))?;

        if !resp.status().is_success() {
            return Err(map_http_error(resp.status().as_u16(), "list", String::new()));
        }
        #[derive(Deserialize)]
        struct ListResp {
            items: Vec<BackupVersionMeta>,
        }
        let body: ListResp = resp
            .json()
            .await
            .map_err(|e| KvendraError::Serialization(format!("list resp: {e}")))?;
        Ok(body.items)
    }

    pub async fn pull(&self, backup_id: &str) -> KvendraResult<Vec<u8>> {
        let url = format!("{}/v1/backups/{backup_id}", self.base_url);
        let resp = self
            .http
            .get(url)
            .bearer_auth(&self.jwt)
            .send()
            .await
            .map_err(|e| KvendraError::Vault(format!("backup pull: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(map_http_error(status, "pull", body));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| KvendraError::Vault(format!("pull body: {e}")))?;
        Ok(bytes.to_vec())
    }

    pub async fn delete(&self, backup_id: &str) -> KvendraResult<()> {
        let url = format!("{}/v1/backups/{backup_id}", self.base_url);
        let resp = self
            .http
            .delete(url)
            .bearer_auth(&self.jwt)
            .send()
            .await
            .map_err(|e| KvendraError::Vault(format!("backup delete: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(map_http_error(status, "delete", body));
        }
        Ok(())
    }

    async fn parse_meta_response(
        &self,
        resp: reqwest::Response,
    ) -> KvendraResult<BackupVersionMeta> {
        let status = resp.status().as_u16();
        if status == 409 {
            let body = resp.text().await.unwrap_or_default();
            return Err(KvendraError::Vault(format!(
                "BackupConflict: remote etag differs from local parent — \
                 server response: {body}"
            )));
        }
        if status == 413 {
            return Err(KvendraError::Vault(
                "BackupTooLarge: bundle exceeds 10 MiB API gateway limit".into(),
            ));
        }
        if status == 429 {
            return Err(KvendraError::Vault(
                "RateLimited: max 1 push per minute".into(),
            ));
        }
        if status == 401 || status == 403 {
            return Err(KvendraError::Vault(
                "NotProAuthenticated: run `kvendra login --pro`".into(),
            ));
        }
        if !(200..300).contains(&status) {
            let body = resp.text().await.unwrap_or_default();
            return Err(map_http_error(status, "push", body));
        }
        let meta: BackupVersionMeta = resp
            .json()
            .await
            .map_err(|e| KvendraError::Serialization(format!("push resp: {e}")))?;
        Ok(meta)
    }
}

fn map_http_error(status: u16, op: &str, body: String) -> KvendraError {
    KvendraError::Vault(format!(
        "BackendError on {op}: status={status} body={body}"
    ))
}

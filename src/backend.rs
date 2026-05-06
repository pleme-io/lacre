//! Backend OCI registry — the upstream lacre proxies to. Trait so
//! tests can use a fake; production uses the HTTP impl.

use async_trait::async_trait;
use bytes::Bytes;

use crate::error::{LacreError, Result};

#[derive(Debug, Clone)]
pub struct BackendResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

#[async_trait]
pub trait Backend: Send + Sync {
    /// Forward a manifest PUT to the backend. The path is the same
    /// path lacre received (e.g. `/v2/myorg/myimage/manifests/v1.2.3`).
    /// `content_type` is the manifest media type; `body` is the raw
    /// bytes — cartorio has already validated them.
    async fn put_manifest(
        &self,
        path: &str,
        content_type: &str,
        body: Bytes,
    ) -> Result<BackendResponse>;

    /// Generic passthrough for everything that isn't a gated path.
    /// Returns the backend's response verbatim.
    async fn passthrough(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: Bytes,
    ) -> Result<BackendResponse>;
}

pub struct HttpBackend {
    base_url: String,
    http: reqwest::Client,
}

impl HttpBackend {
    /// # Errors
    /// Fails if reqwest client construction fails.
    pub fn new(base_url: String) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|e| LacreError::Config(format!("reqwest client: {e}")))?;
        Ok(Self { base_url, http })
    }

    fn join_url(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }
}

#[async_trait]
impl Backend for HttpBackend {
    async fn put_manifest(
        &self,
        path: &str,
        content_type: &str,
        body: Bytes,
    ) -> Result<BackendResponse> {
        let url = self.join_url(path);
        let resp = self
            .http
            .put(&url)
            .header("content-type", content_type)
            .body(body)
            .send()
            .await
            .map_err(|e| LacreError::BackendRequest(format!("PUT {url}: {e}")))?;
        bake_response(resp).await
    }

    async fn passthrough(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: Bytes,
    ) -> Result<BackendResponse> {
        let url = self.join_url(path);
        let m = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|e| LacreError::BackendRequest(format!("invalid method {method}: {e}")))?;
        let mut req = self.http.request(m, &url);
        for (k, v) in headers {
            // Skip hop-by-hop and connection-specific headers; reqwest
            // sets host itself and we own content-length / transfer-encoding.
            if matches!(
                k.to_ascii_lowercase().as_str(),
                "host" | "content-length" | "transfer-encoding" | "connection"
            ) {
                continue;
            }
            req = req.header(k, v);
        }
        let resp = req
            .body(body)
            .send()
            .await
            .map_err(|e| LacreError::BackendRequest(format!("{method} {url}: {e}")))?;
        bake_response(resp).await
    }
}

async fn bake_response(resp: reqwest::Response) -> Result<BackendResponse> {
    let status = resp.status().as_u16();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|s| (k.as_str().to_string(), s.to_string()))
        })
        .collect();
    let body = resp
        .bytes()
        .await
        .map_err(|e| LacreError::BackendRequest(format!("read body: {e}")))?;
    Ok(BackendResponse {
        status,
        headers,
        body,
    })
}

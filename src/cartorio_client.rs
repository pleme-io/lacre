//! Typed cartorio client. The trait is the seam — production uses
//! `HttpCartorioClient`; tests use a fake.

use async_trait::async_trait;
use serde::Deserialize;

use crate::error::{LacreError, Result};

/// Status of an artifact as cartorio reports it. Mirrors
/// `cartorio::core::types::ArtifactStatus` but typed locally so lacre
/// doesn't take a runtime dep on cartorio's full crate (only its wire
/// format).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CartorioStatus {
    Active,
    Revoked,
    Quarantined,
    Superseded,
}

/// What lacre needs to know about an artifact to decide gate outcome.
#[derive(Debug, Clone, Deserialize)]
pub struct ArtifactSnapshot {
    pub id: String,
    pub digest: String,
    pub status: CartorioStatus,
    /// Org the artifact is registered under (lacre's instance is
    /// pinned to one org via config).
    pub org: String,
}

#[async_trait]
pub trait CartorioClient: Send + Sync {
    /// Lookup an artifact by its content digest. Returns `Ok(None)` if
    /// no artifact with that digest is registered. Returns
    /// `Ok(Some(snapshot))` regardless of status — the caller decides
    /// whether to admit based on the status field.
    async fn lookup_by_digest(&self, digest: &str) -> Result<Option<ArtifactSnapshot>>;
}

pub struct HttpCartorioClient {
    base_url: String,
    http: reqwest::Client,
}

impl HttpCartorioClient {
    /// # Errors
    /// Fails if the underlying reqwest client cannot be built.
    pub fn new(base_url: String) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|e| LacreError::Config(format!("reqwest client: {e}")))?;
        Ok(Self { base_url, http })
    }
}

#[async_trait]
impl CartorioClient for HttpCartorioClient {
    async fn lookup_by_digest(&self, digest: &str) -> Result<Option<ArtifactSnapshot>> {
        let url = format!(
            "{}/api/v1/artifacts/by-digest/{}",
            self.base_url.trim_end_matches('/'),
            urlencode(digest)
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| LacreError::CartorioRequest(format!("GET {url}: {e}")))?;
        match resp.status().as_u16() {
            200 => {
                let snapshot = resp.json::<ArtifactSnapshot>().await.map_err(|e| {
                    LacreError::CartorioRequest(format!("parse {url}: {e}"))
                })?;
                Ok(Some(snapshot))
            }
            404 => Ok(None),
            code => Err(LacreError::CartorioRequest(format!(
                "unexpected status {code} from {url}"
            ))),
        }
    }
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                use std::fmt::Write;
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

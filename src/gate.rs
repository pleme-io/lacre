//! The gate decision: given the bytes of an OCI manifest, compute its
//! sha256 digest, ask cartorio about it, decide accept/reject.

use sha2::{Digest, Sha256};

use crate::cartorio_client::{CartorioClient, CartorioStatus};
use crate::error::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateDecision {
    /// Forward the manifest to the backend.
    Allow {
        digest: String,
        artifact_id: String,
    },
    /// Reject with 403; reason is operator-readable and safe to return
    /// to the client.
    Reject { digest: String, reason: String },
}

#[must_use]
pub fn manifest_digest(body: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(body);
    let hex = hex::encode(h.finalize());
    format!("sha256:{hex}")
}

/// # Errors
/// Returns the cartorio client's error if the lookup fails. Network
/// errors are returned as-is — the caller maps them to 503.
pub async fn decide<C: CartorioClient + ?Sized>(
    client: &C,
    expected_org: &str,
    body: &[u8],
) -> Result<GateDecision> {
    let digest = manifest_digest(body);
    let snapshot = client.lookup_by_digest(&digest).await?;
    let Some(s) = snapshot else {
        return Ok(GateDecision::Reject {
            digest,
            reason: "no compliant listing for this digest".into(),
        });
    };
    if s.org != expected_org {
        return Ok(GateDecision::Reject {
            digest,
            reason: format!(
                "artifact registered under org {} but this lacre instance gates org {}",
                s.org, expected_org
            ),
        });
    }
    match s.status {
        CartorioStatus::Active => Ok(GateDecision::Allow {
            digest,
            artifact_id: s.id,
        }),
        CartorioStatus::Revoked => Ok(GateDecision::Reject {
            digest,
            reason: format!("artifact {} is revoked", s.id),
        }),
        CartorioStatus::Quarantined => Ok(GateDecision::Reject {
            digest,
            reason: format!("artifact {} is quarantined", s.id),
        }),
        CartorioStatus::Superseded => Ok(GateDecision::Reject {
            digest,
            reason: format!("artifact {} has been superseded", s.id),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Arc;

    struct Fake {
        snap: Option<crate::cartorio_client::ArtifactSnapshot>,
    }

    #[async_trait]
    impl CartorioClient for Fake {
        async fn lookup_by_digest(
            &self,
            _digest: &str,
        ) -> Result<Option<crate::cartorio_client::ArtifactSnapshot>> {
            Ok(self.snap.clone())
        }
    }

    #[test]
    fn manifest_digest_is_sha256_prefixed() {
        let d = manifest_digest(b"hello");
        assert!(d.starts_with("sha256:"));
        assert_eq!(d.len(), "sha256:".len() + 64);
    }

    #[test]
    fn manifest_digest_is_deterministic() {
        assert_eq!(manifest_digest(b"abc"), manifest_digest(b"abc"));
        assert_ne!(manifest_digest(b"abc"), manifest_digest(b"abd"));
    }

    #[tokio::test]
    async fn unknown_digest_rejected() {
        let f: Arc<dyn CartorioClient> = Arc::new(Fake { snap: None });
        let d = decide(&*f, "pleme-io", b"some-body").await.unwrap();
        match d {
            GateDecision::Reject { reason, .. } => assert!(reason.contains("no compliant listing")),
            GateDecision::Allow { .. } => panic!("expected reject"),
        }
    }

    #[tokio::test]
    async fn active_digest_for_correct_org_allowed() {
        let f: Arc<dyn CartorioClient> = Arc::new(Fake {
            snap: Some(crate::cartorio_client::ArtifactSnapshot {
                id: "art-0".into(),
                digest: manifest_digest(b"x"),
                status: CartorioStatus::Active,
                org: "pleme-io".into(),
            }),
        });
        let d = decide(&*f, "pleme-io", b"x").await.unwrap();
        assert!(matches!(d, GateDecision::Allow { .. }));
    }

    #[tokio::test]
    async fn active_digest_wrong_org_rejected() {
        let f: Arc<dyn CartorioClient> = Arc::new(Fake {
            snap: Some(crate::cartorio_client::ArtifactSnapshot {
                id: "art-0".into(),
                digest: manifest_digest(b"x"),
                status: CartorioStatus::Active,
                org: "other-org".into(),
            }),
        });
        let d = decide(&*f, "pleme-io", b"x").await.unwrap();
        match d {
            GateDecision::Reject { reason, .. } => assert!(reason.contains("registered under")),
            GateDecision::Allow { .. } => panic!("wrong-org artifact must not be admitted"),
        }
    }

    #[tokio::test]
    async fn revoked_digest_rejected() {
        let f: Arc<dyn CartorioClient> = Arc::new(Fake {
            snap: Some(crate::cartorio_client::ArtifactSnapshot {
                id: "art-rev".into(),
                digest: "sha256:beef".into(),
                status: CartorioStatus::Revoked,
                org: "pleme-io".into(),
            }),
        });
        let d = decide(&*f, "pleme-io", b"x").await.unwrap();
        match d {
            GateDecision::Reject { reason, .. } => assert!(reason.contains("revoked")),
            GateDecision::Allow { .. } => panic!("revoked must not be allowed"),
        }
    }

    #[tokio::test]
    async fn quarantined_digest_rejected() {
        let f: Arc<dyn CartorioClient> = Arc::new(Fake {
            snap: Some(crate::cartorio_client::ArtifactSnapshot {
                id: "art-q".into(),
                digest: "sha256:beef".into(),
                status: CartorioStatus::Quarantined,
                org: "pleme-io".into(),
            }),
        });
        let d = decide(&*f, "pleme-io", b"x").await.unwrap();
        match d {
            GateDecision::Reject { reason, .. } => assert!(reason.contains("quarantined")),
            GateDecision::Allow { .. } => panic!("quarantined must not be allowed"),
        }
    }

    #[tokio::test]
    async fn superseded_digest_rejected() {
        let f: Arc<dyn CartorioClient> = Arc::new(Fake {
            snap: Some(crate::cartorio_client::ArtifactSnapshot {
                id: "art-s".into(),
                digest: "sha256:beef".into(),
                status: CartorioStatus::Superseded,
                org: "pleme-io".into(),
            }),
        });
        let d = decide(&*f, "pleme-io", b"x").await.unwrap();
        match d {
            GateDecision::Reject { reason, .. } => assert!(reason.contains("superseded")),
            GateDecision::Allow { .. } => panic!("superseded must not be allowed"),
        }
    }
}

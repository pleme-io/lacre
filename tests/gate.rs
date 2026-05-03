//! End-to-end gate tests — wire the full axum router with a fake
//! cartorio + fake backend, drive HTTP requests through it, assert
//! every gate path produces the right outcome.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use bytes::Bytes;
use http_body_util::BodyExt;
use lacre::{
    backend::{Backend, BackendResponse},
    cartorio_client::{ArtifactSnapshot, CartorioClient, CartorioStatus},
    gate::manifest_digest,
    routes::{AppState, router},
};
use tower::ServiceExt;

#[derive(Default)]
struct FakeCartorio {
    by_digest: Mutex<HashMap<String, ArtifactSnapshot>>,
}

impl FakeCartorio {
    fn register(&self, snap: ArtifactSnapshot) {
        self.by_digest.lock().unwrap().insert(snap.digest.clone(), snap);
    }
}

#[async_trait]
impl CartorioClient for FakeCartorio {
    async fn lookup_by_digest(&self, digest: &str) -> lacre::Result<Option<ArtifactSnapshot>> {
        Ok(self.by_digest.lock().unwrap().get(digest).cloned())
    }
}

#[derive(Default)]
struct FakeBackend {
    received_puts: Mutex<Vec<(String, Bytes)>>,
    passthrough_calls: Mutex<Vec<(String, String)>>,
}

#[async_trait]
impl Backend for FakeBackend {
    async fn put_manifest(
        &self,
        path: &str,
        _content_type: &str,
        body: Bytes,
    ) -> lacre::Result<BackendResponse> {
        self.received_puts.lock().unwrap().push((path.to_string(), body.clone()));
        let digest = manifest_digest(&body);
        Ok(BackendResponse {
            status: 201,
            headers: vec![
                ("docker-content-digest".to_string(), digest.clone()),
                ("location".to_string(), format!("{path}?digest={digest}")),
            ],
            body: Bytes::new(),
        })
    }

    async fn passthrough(
        &self,
        method: &str,
        path: &str,
        _headers: &[(String, String)],
        _body: Bytes,
    ) -> lacre::Result<BackendResponse> {
        self.passthrough_calls
            .lock()
            .unwrap()
            .push((method.to_string(), path.to_string()));
        Ok(BackendResponse {
            status: 200,
            headers: vec![("docker-distribution-api-version".to_string(), "registry/2.0".to_string())],
            body: Bytes::from_static(b"{}"),
        })
    }
}

fn build_state(
    cartorio: Arc<dyn CartorioClient>,
    backend: Arc<FakeBackend>,
    org: &str,
) -> (Arc<AppState>, Arc<FakeBackend>) {
    let backend_dyn: Arc<dyn Backend> = backend.clone();
    let state = Arc::new(AppState {
        cartorio,
        backend: backend_dyn,
        org: org.into(),
        max_manifest_bytes: 4 * 1024 * 1024,
    });
    (state, backend)
}

const ORG: &str = "pleme-io";
const COMPLIANT_MANIFEST: &[u8] = br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","size":1},"layers":[]}"#;

#[tokio::test]
async fn compliant_manifest_is_forwarded_to_backend() {
    let cartorio = Arc::new(FakeCartorio::default());
    let digest = manifest_digest(COMPLIANT_MANIFEST);
    cartorio.register(ArtifactSnapshot {
        id: "art-compliant".into(),
        digest: digest.clone(),
        status: CartorioStatus::Active,
        org: ORG.into(),
    });

    let (state, backend) = build_state(cartorio, Arc::new(FakeBackend::default()), ORG);
    let app = router(state);

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/v2/myorg/myimage/manifests/v1.0.0")
        .header("content-type", "application/vnd.oci.image.manifest.v1+json")
        .body(Body::from(COMPLIANT_MANIFEST))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let received = backend.received_puts.lock().unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].0, "/v2/myorg/myimage/manifests/v1.0.0");
    assert_eq!(received[0].1.as_ref(), COMPLIANT_MANIFEST);
}

#[tokio::test]
async fn unknown_digest_is_rejected_403_and_not_forwarded() {
    let cartorio = Arc::new(FakeCartorio::default());
    // No registration → cartorio returns None.
    let (state, backend) = build_state(cartorio, Arc::new(FakeBackend::default()), ORG);
    let app = router(state);

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/v2/myorg/myimage/manifests/v1.0.0")
        .header("content-type", "application/vnd.oci.image.manifest.v1+json")
        .body(Body::from(COMPLIANT_MANIFEST))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let msg = body["errors"][0]["message"].as_str().unwrap();
    assert!(msg.contains("no compliant listing"), "msg was {msg}");

    assert!(
        backend.received_puts.lock().unwrap().is_empty(),
        "backend MUST NOT have been called"
    );
}

#[tokio::test]
async fn revoked_digest_is_rejected_403() {
    let cartorio = Arc::new(FakeCartorio::default());
    let digest = manifest_digest(COMPLIANT_MANIFEST);
    cartorio.register(ArtifactSnapshot {
        id: "art-rev".into(),
        digest,
        status: CartorioStatus::Revoked,
        org: ORG.into(),
    });
    let (state, backend) = build_state(cartorio, Arc::new(FakeBackend::default()), ORG);
    let app = router(state);

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/v2/myorg/myimage/manifests/v1.0.0")
        .header("content-type", "application/vnd.oci.image.manifest.v1+json")
        .body(Body::from(COMPLIANT_MANIFEST))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let msg = body["errors"][0]["message"].as_str().unwrap();
    assert!(msg.contains("revoked"), "msg was {msg}");
    assert!(backend.received_puts.lock().unwrap().is_empty());
}

#[tokio::test]
async fn quarantined_digest_is_rejected_403() {
    let cartorio = Arc::new(FakeCartorio::default());
    let digest = manifest_digest(COMPLIANT_MANIFEST);
    cartorio.register(ArtifactSnapshot {
        id: "art-q".into(),
        digest,
        status: CartorioStatus::Quarantined,
        org: ORG.into(),
    });
    let (state, backend) = build_state(cartorio, Arc::new(FakeBackend::default()), ORG);
    let app = router(state);

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/v2/myorg/myimage/manifests/v1.0.0")
        .header("content-type", "application/vnd.oci.image.manifest.v1+json")
        .body(Body::from(COMPLIANT_MANIFEST))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let msg = body["errors"][0]["message"].as_str().unwrap();
    assert!(msg.contains("quarantined"), "msg was {msg}");
    assert!(backend.received_puts.lock().unwrap().is_empty());
}

#[tokio::test]
async fn wrong_org_is_rejected_403() {
    let cartorio = Arc::new(FakeCartorio::default());
    let digest = manifest_digest(COMPLIANT_MANIFEST);
    cartorio.register(ArtifactSnapshot {
        id: "art-other".into(),
        digest,
        status: CartorioStatus::Active,
        org: "other-org".into(),
    });
    let (state, backend) = build_state(cartorio, Arc::new(FakeBackend::default()), ORG);
    let app = router(state);

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/v2/myorg/myimage/manifests/v1.0.0")
        .header("content-type", "application/vnd.oci.image.manifest.v1+json")
        .body(Body::from(COMPLIANT_MANIFEST))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let msg = body["errors"][0]["message"].as_str().unwrap();
    assert!(msg.contains("registered under"), "msg was {msg}");
    assert!(backend.received_puts.lock().unwrap().is_empty());
}

#[tokio::test]
async fn manifest_get_passes_through_unchanged() {
    let cartorio = Arc::new(FakeCartorio::default());
    let (state, backend) = build_state(cartorio, Arc::new(FakeBackend::default()), ORG);
    let app = router(state);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/v2/myorg/myimage/manifests/v1.0.0")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let calls = backend.passthrough_calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "GET");
    assert_eq!(calls[0].1, "/v2/myorg/myimage/manifests/v1.0.0");
    // Crucial: backend was reached, so cartorio was NOT consulted on a
    // GET — gate is PUT-only.
    assert!(backend.received_puts.lock().unwrap().is_empty());
}

#[tokio::test]
async fn blob_paths_pass_through_unchanged() {
    let cartorio = Arc::new(FakeCartorio::default());
    let (state, backend) = build_state(cartorio, Arc::new(FakeBackend::default()), ORG);
    let app = router(state);

    // Blob HEAD
    let req = Request::builder()
        .method(Method::HEAD)
        .uri("/v2/myorg/myimage/blobs/sha256:cafebabe")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Blob upload init
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v2/myorg/myimage/blobs/uploads/")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let calls = backend.passthrough_calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].0, "HEAD");
    assert_eq!(calls[1].0, "POST");
    assert!(backend.received_puts.lock().unwrap().is_empty());
}

#[tokio::test]
async fn v2_version_check_passes_through() {
    let cartorio = Arc::new(FakeCartorio::default());
    let (state, backend) = build_state(cartorio, Arc::new(FakeBackend::default()), ORG);
    let app = router(state);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/v2/")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let calls = backend.passthrough_calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1, "/v2/");
}

#[tokio::test]
async fn put_blob_is_not_gated() {
    // Blob PUTs (finalizing an upload) are NOT gated — only manifest
    // PUTs. The image only "joins the namespace" when the manifest
    // lands, so blob writes can be backend-internal until then.
    let cartorio = Arc::new(FakeCartorio::default());
    let (state, backend) = build_state(cartorio, Arc::new(FakeBackend::default()), ORG);
    let app = router(state);

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/v2/myorg/myimage/blobs/uploads/abc?digest=sha256:cafebabe")
        .body(Body::from(&b"some-blob-bytes"[..]))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(backend.received_puts.lock().unwrap().is_empty()); // no manifest PUT
    let calls = backend.passthrough_calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "PUT");
}

#[tokio::test]
async fn manifest_too_large_is_rejected_413_and_not_forwarded() {
    let cartorio = Arc::new(FakeCartorio::default());
    let backend = Arc::new(FakeBackend::default());
    let backend_dyn: Arc<dyn Backend> = backend.clone();
    let state = Arc::new(AppState {
        cartorio,
        backend: backend_dyn,
        org: ORG.into(),
        max_manifest_bytes: 1024,
    });
    let app = router(state);

    let big = vec![b'a'; 2048];
    let req = Request::builder()
        .method(Method::PUT)
        .uri("/v2/myorg/myimage/manifests/v1.0.0")
        .header("content-type", "application/vnd.oci.image.manifest.v1+json")
        .body(Body::from(big))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(backend.received_puts.lock().unwrap().is_empty());
}

#[tokio::test]
async fn healthz_returns_ok() {
    let cartorio = Arc::new(FakeCartorio::default());
    let (state, _backend) = build_state(cartorio, Arc::new(FakeBackend::default()), ORG);
    let app = router(state);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/healthz")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

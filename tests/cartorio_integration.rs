//! End-to-end integration: real lacre process talking to a real
//! cartorio process talking to a mock OCI backend, all wired over
//! actual TCP. Exercises the production HTTP path that the previous
//! tests stubbed with fakes.
//!
//! Topology:
//!
//!   ┌──────────┐       PUT manifest        ┌────────────┐
//!   │  client  │ ─────────────────────────▶│   lacre    │
//!   └──────────┘                           │  (real)    │
//!                                          └─────┬──────┘
//!                                                │
//!            `cartorio.lookup_by_digest(...)`    │
//!                                                ▼
//!                                          ┌────────────┐
//!                                          │  cartorio  │
//!                                          │  (real)    │
//!                                          └─────┬──────┘
//!                                                │ status=Active+match
//!                                                ▼
//!                                          ┌────────────┐
//!                                          │ mock OCI   │
//!                                          │  backend   │
//!                                          └────────────┘
//!
//! Each test seeds cartorio's Store directly (bypassing the HTTP admit
//! handshake) so it can place a digest in any status without needing
//! to compute valid signatures.

use std::sync::Arc;
use std::time::Duration;

use axum::{Router, extract::Request, response::Response, routing::any};
use cartorio::{
    api::router as cartorio_router,
    config::RegistryConfig,
    core::types::{
        AdmissionEvent, ArtifactKind, ArtifactState, ArtifactStatus, AttestationChain,
        BuildAttestation, ComplianceAttestation, ComplianceStatus, ImageAttestation, LedgerEvent,
        ModifierIdentity, RevocationEvent, SignedRoot, SigningAlgorithm, SourceAttestation,
    },
    merkle::{compose_admission_event_root, compose_revocation_event_root, compose_state_leaf_root},
    state::AppState as CartorioAppState,
};
use lacre::{
    Backend, HttpBackend, HttpCartorioClient,
    routes::{AppState as LacreAppState, router as lacre_router},
};
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use tameshi::hash::Blake3Hash;

const ORG: &str = "pleme-io";

// ─── helpers: cartorio fixtures ─────────────────────────────────────

fn full_chain() -> AttestationChain {
    AttestationChain {
        source: Some(SourceAttestation {
            git_commit: "abc123".into(),
            tree_hash: Blake3Hash::digest(b"tree"),
            flake_lock_hash: Blake3Hash::digest(b"lock"),
        }),
        build: Some(BuildAttestation {
            closure_hash: Blake3Hash::digest(b"closure"),
            sbom_hash: Blake3Hash::digest(b"sbom"),
            slsa_level: 3,
        }),
        image: Some(ImageAttestation {
            oci_digest: "sha256:beef".into(),
            cosign_signature_ref: "ref:sig".into(),
            slsa_provenance_ref: "ref:prov".into(),
        }),
        compliance: Some(ComplianceAttestation {
            framework: "NIST_800_53".into(),
            baseline: "high".into(),
            profile: "nist-800-53-high".into(),
            result_hash: Blake3Hash::digest(b"compliance-passed"),
            status: ComplianceStatus::Compliant,
        }),
    }
}

/// Construct a fully-admitted `ArtifactState` + `LedgerEvent` pair for a
/// given content digest. The `signed_root.signature` is a placeholder
/// (cartorio's `verify_signed_root_shape` only checks length/non-empty).
fn admitted_artifact(digest: &str, org: &str, name: &str) -> (ArtifactState, LedgerEvent) {
    let chain = full_chain();
    let modifier = ModifierIdentity::Publisher {
        publisher_id: "alice@pleme.io".into(),
    };
    let now = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    let id = format!("art-{name}");

    let state_root = compose_state_leaf_root(
        ArtifactKind::OciImage.name(),
        name,
        "1.0.0",
        "alice@pleme.io",
        org,
        digest,
        &chain,
        ArtifactStatus::Active,
        &modifier,
        now.timestamp(),
    );
    let event_root = compose_admission_event_root(
        &id,
        ArtifactKind::OciImage.name(),
        name,
        "1.0.0",
        "alice@pleme.io",
        org,
        digest,
        &chain,
        now.timestamp(),
    );
    let signed = SignedRoot {
        root: state_root.clone(),
        signature: "a".repeat(64),
        algorithm: SigningAlgorithm::Blake3KeyedHmac,
        signer_id: "publisher:alice@pleme.io".into(),
        signed_at: now,
    };
    (
        ArtifactState {
            id: id.clone(),
            kind: ArtifactKind::OciImage,
            name: name.into(),
            version: "1.0.0".into(),
            publisher_id: "alice@pleme.io".into(),
            org: org.into(),
            digest: digest.into(),
            attestation: chain.clone(),
            status: ArtifactStatus::Active,
            last_modified_at: now,
            last_modifier: modifier,
            composed_root: state_root.clone(),
            signed_root: signed.clone(),
            admitted_at: now,
        },
        LedgerEvent::Admission(AdmissionEvent {
            event_id: format!("evt-admit-{name}"),
            artifact_id: id,
            kind: ArtifactKind::OciImage,
            name: name.into(),
            version: "1.0.0".into(),
            publisher_id: "alice@pleme.io".into(),
            org: org.into(),
            digest: digest.into(),
            attestation: chain,
            composed_root: event_root.clone(),
            signed_root: SignedRoot {
                root: event_root,
                ..signed
            },
            created_at: now,
        }),
    )
}

fn revocation_for(state: &ArtifactState) -> (ArtifactState, LedgerEvent) {
    let modifier = ModifierIdentity::Pki {
        signer_id: "pleme-io".into(),
    };
    let now = chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let new_state_root = compose_state_leaf_root(
        state.kind.name(),
        &state.name,
        &state.version,
        &state.publisher_id,
        &state.org,
        &state.digest,
        &state.attestation,
        ArtifactStatus::Revoked,
        &modifier,
        now.timestamp(),
    );
    let event_root = compose_revocation_event_root(&state.id, "test-revoke", &modifier, now.timestamp());
    let signed = SignedRoot {
        root: new_state_root.clone(),
        signature: "b".repeat(64),
        algorithm: SigningAlgorithm::Blake3KeyedHmac,
        signer_id: modifier.signer_label(),
        signed_at: now,
    };
    (
        ArtifactState {
            status: ArtifactStatus::Revoked,
            last_modified_at: now,
            last_modifier: modifier.clone(),
            composed_root: new_state_root,
            signed_root: signed.clone(),
            ..state.clone()
        },
        LedgerEvent::Revocation(RevocationEvent {
            event_id: format!("evt-rev-{}", state.id),
            artifact_id: state.id.clone(),
            reason: "test-revoke".into(),
            modifier: modifier.clone(),
            composed_root: event_root.clone(),
            signed_root: SignedRoot {
                root: event_root,
                ..signed
            },
            created_at: now,
        }),
    )
}

fn manifest_digest(body: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(body);
    format!("sha256:{}", hex::encode(h.finalize()))
}

// ─── helpers: spawn three real services on random ports ────────────

#[derive(Default)]
struct MockBackend {
    received: Mutex<Vec<(String, String, Vec<u8>)>>, // (method, path, body)
}

async fn spawn_mock_backend() -> (String, Arc<MockBackend>) {
    let backend = Arc::new(MockBackend::default());
    let backend_clone = backend.clone();
    let app: Router = Router::new().route(
        "/{*rest}",
        any(move |req: Request| {
            let backend = backend_clone.clone();
            async move {
                let method = req.method().as_str().to_string();
                let path = req.uri().path().to_string();
                let body = axum::body::to_bytes(req.into_body(), 4 * 1024 * 1024)
                    .await
                    .unwrap_or_default();
                backend
                    .received
                    .lock()
                    .unwrap()
                    .push((method, path, body.to_vec()));
                Response::builder()
                    .status(201)
                    .header("docker-content-digest", "sha256:fake")
                    .body(axum::body::Body::from("mock-backend-ok"))
                    .unwrap()
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (url, backend)
}

async fn spawn_cartorio(state: Arc<CartorioAppState>) -> String {
    let app = cartorio_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    url
}

async fn spawn_lacre(cartorio_url: String, backend_url: String, org: &str) -> String {
    let cartorio_client = HttpCartorioClient::new(cartorio_url).unwrap();
    let backend: Arc<dyn Backend> = Arc::new(HttpBackend::new(backend_url).unwrap());
    let state = Arc::new(LacreAppState {
        cartorio: Arc::new(cartorio_client),
        backend,
        org: org.into(),
        max_manifest_bytes: 4 * 1024 * 1024,
    });
    let app = lacre_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    url
}

async fn build_cartorio(seed: impl FnOnce(&cartorio::store::Store) -> Vec<(ArtifactState, LedgerEvent)>) -> Arc<CartorioAppState> {
    let cfg = RegistryConfig {
        org: ORG.into(),
        listen: "127.0.0.1:0".into(),
        pki_url: None,
    };
    let app = CartorioAppState::new(cfg);
    let pairs = seed(&app.store);
    for (s, e) in pairs {
        app.store.admit(s, e).await;
    }
    app
}

// reqwest with a short timeout so misconfigured tests fail fast.
fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

// ─── the actual tests ──────────────────────────────────────────────

const TEST_MANIFEST: &[u8] = br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","size":1},"layers":[]}"#;

#[tokio::test]
async fn end_to_end_compliant_image_flows_through() {
    let digest = manifest_digest(TEST_MANIFEST);

    let cartorio_state = build_cartorio(|_store| {
        vec![admitted_artifact(&digest, ORG, "myimage")]
    })
    .await;

    let (backend_url, backend_recorder) = spawn_mock_backend().await;
    let cartorio_url = spawn_cartorio(cartorio_state).await;
    let lacre_url = spawn_lacre(cartorio_url.clone(), backend_url, ORG).await;

    // sanity: cartorio is up + reports the artifact at this digest
    let resp = http_client()
        .get(format!("{cartorio_url}/api/v1/artifacts/by-digest/{digest}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // push manifest through lacre
    let resp = http_client()
        .put(format!("{lacre_url}/v2/myorg/myimage/manifests/v1.0.0"))
        .header("content-type", "application/vnd.oci.image.manifest.v1+json")
        .body(TEST_MANIFEST.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "compliant manifest must reach backend");

    // backend received the push
    let received = backend_recorder.received.lock().unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].0, "PUT");
    assert_eq!(received[0].1, "/v2/myorg/myimage/manifests/v1.0.0");
    assert_eq!(received[0].2, TEST_MANIFEST);
}

#[tokio::test]
async fn end_to_end_unknown_digest_blocked_without_touching_backend() {
    // No artifact in cartorio at all.
    let cartorio_state = build_cartorio(|_store| vec![]).await;
    let (backend_url, backend_recorder) = spawn_mock_backend().await;
    let cartorio_url = spawn_cartorio(cartorio_state).await;
    let lacre_url = spawn_lacre(cartorio_url, backend_url, ORG).await;

    let resp = http_client()
        .put(format!("{lacre_url}/v2/myorg/myimage/manifests/v1.0.0"))
        .header("content-type", "application/vnd.oci.image.manifest.v1+json")
        .body(TEST_MANIFEST.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body: serde_json::Value = resp.json().await.unwrap();
    let msg = body["errors"][0]["message"].as_str().unwrap();
    assert!(msg.contains("no compliant listing"), "got msg: {msg}");

    // backend MUST not have been called for the manifest
    let received = backend_recorder.received.lock().unwrap();
    assert!(
        received.iter().all(|(_, p, _)| !p.contains("/manifests/")),
        "backend must not see a manifest PUT for unknown digest"
    );
}

#[tokio::test]
async fn end_to_end_revoked_digest_blocked() {
    let digest = manifest_digest(TEST_MANIFEST);

    let cartorio_state = build_cartorio(|_store| {
        vec![admitted_artifact(&digest, ORG, "myimage-rev")]
    })
    .await;

    // After admission, revoke the artifact.
    let live = cartorio_state
        .store
        .get_artifact_by_digest(&digest)
        .await
        .expect("admitted");
    let (rev_state, rev_event) = revocation_for(&live);
    cartorio_state.store.mutate(rev_state, rev_event).await;

    let (backend_url, backend_recorder) = spawn_mock_backend().await;
    let cartorio_url = spawn_cartorio(cartorio_state).await;
    let lacre_url = spawn_lacre(cartorio_url, backend_url, ORG).await;

    let resp = http_client()
        .put(format!("{lacre_url}/v2/myorg/myimage/manifests/v1.0.0"))
        .header("content-type", "application/vnd.oci.image.manifest.v1+json")
        .body(TEST_MANIFEST.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body: serde_json::Value = resp.json().await.unwrap();
    let msg = body["errors"][0]["message"].as_str().unwrap();
    assert!(msg.contains("revoked"), "got msg: {msg}");

    let received = backend_recorder.received.lock().unwrap();
    assert!(received.iter().all(|(_, p, _)| !p.contains("/manifests/")));
}

#[tokio::test]
async fn end_to_end_wrong_org_blocked() {
    let digest = manifest_digest(TEST_MANIFEST);

    // Artifact is admitted under "other-org", but lacre gates "pleme-io".
    let cartorio_state = build_cartorio(|_store| {
        vec![admitted_artifact(&digest, "other-org", "myimage-other")]
    })
    .await;

    let (backend_url, backend_recorder) = spawn_mock_backend().await;
    let cartorio_url = spawn_cartorio(cartorio_state).await;
    let lacre_url = spawn_lacre(cartorio_url, backend_url, ORG).await;

    let resp = http_client()
        .put(format!("{lacre_url}/v2/myorg/myimage/manifests/v1.0.0"))
        .header("content-type", "application/vnd.oci.image.manifest.v1+json")
        .body(TEST_MANIFEST.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let body: serde_json::Value = resp.json().await.unwrap();
    let msg = body["errors"][0]["message"].as_str().unwrap();
    assert!(msg.contains("registered under"), "got msg: {msg}");
    assert!(
        backend_recorder
            .received
            .lock()
            .unwrap()
            .iter()
            .all(|(_, p, _)| !p.contains("/manifests/"))
    );
}

#[tokio::test]
async fn end_to_end_pull_path_does_not_consult_cartorio() {
    // Even if cartorio is up and has nothing for the digest, GET
    // requests must NOT trigger a cartorio lookup — they pass straight
    // through to the backend.
    let cartorio_state = build_cartorio(|_store| vec![]).await;
    let (backend_url, backend_recorder) = spawn_mock_backend().await;
    let cartorio_url = spawn_cartorio(cartorio_state).await;
    let lacre_url = spawn_lacre(cartorio_url, backend_url, ORG).await;

    let resp = http_client()
        .get(format!("{lacre_url}/v2/myorg/myimage/manifests/v1.0.0"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201); // mock backend always returns 201
    let received = backend_recorder.received.lock().unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].0, "GET");
}

#[tokio::test]
async fn end_to_end_lifecycle_admit_then_revoke_changes_gate_outcome() {
    // The crux: same client, same digest, two pushes — between them
    // cartorio's status flips from Active to Revoked. Lacre must
    // honor the live status, not a cached one.
    let digest = manifest_digest(TEST_MANIFEST);

    let cartorio_state = build_cartorio(|_store| {
        vec![admitted_artifact(&digest, ORG, "myimage-lifecycle")]
    })
    .await;
    let (backend_url, backend_recorder) = spawn_mock_backend().await;
    let cartorio_url = spawn_cartorio(cartorio_state.clone()).await;
    let lacre_url = spawn_lacre(cartorio_url, backend_url, ORG).await;

    // First push: should succeed.
    let resp = http_client()
        .put(format!("{lacre_url}/v2/myorg/myimage/manifests/v1.0.0"))
        .header("content-type", "application/vnd.oci.image.manifest.v1+json")
        .body(TEST_MANIFEST.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    assert_eq!(backend_recorder.received.lock().unwrap().len(), 1);

    // Now revoke directly in cartorio's store.
    let live = cartorio_state
        .store
        .get_artifact_by_digest(&digest)
        .await
        .unwrap();
    let (rev_state, rev_event) = revocation_for(&live);
    cartorio_state.store.mutate(rev_state, rev_event).await;

    // Second push: must now be rejected.
    let resp = http_client()
        .put(format!("{lacre_url}/v2/myorg/myimage/manifests/v2.0.0"))
        .header("content-type", "application/vnd.oci.image.manifest.v1+json")
        .body(TEST_MANIFEST.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Backend never saw the second manifest PUT.
    assert_eq!(backend_recorder.received.lock().unwrap().len(), 1);
}

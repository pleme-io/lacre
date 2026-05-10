//! **Phase F demo capture — lacre evil-byte 403.**
//!
//! Spins up a real cartorio process (in-memory), a real lacre process,
//! and a mock OCI backend, all on random ports. Pushes a legit
//! manifest (admitted in cartorio), then pushes EVIL bytes claiming the
//! same digest in the URL reference. Lacre hashes the actual body,
//! sees the body's digest is not Active in cartorio, and 403s.
//!
//! Run via:
//!     cargo run --release --example evil_byte_demo > docs/evil-byte-demo.txt
//!
//! Output is the canonical operator-facing transcript: every URL,
//! every status code, every response body. Reproducible because the
//! mock backend is deterministic and the seed is hardcoded.

use cartorio::testing::{admitted_artifact, spawn_cartorio_server};
use lacre::testing::{spawn_lacre, spawn_mock_backend};
use sha2::{Digest, Sha256};

const ORG: &str = "pleme-io";

fn manifest_digest(body: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(body);
    format!("sha256:{}", hex::encode(h.finalize()))
}



#[tokio::main]
async fn main() {
    println!("# lacre evil-byte 403 — captured demonstration");
    println!();
    println!("Stack: real cartorio + real lacre + mock OCI backend, all over real TCP.");
    println!("Adversary: pushes EVIL bytes but URL-claims a known-good digest.");
    println!("Expected: lacre hashes the body (not the URL), sees the body");
    println!("          digest is not Active in cartorio, returns 403.");
    println!();

    // ── Setup ──────────────────────────────────────────────────────
    let (backend_url, backend_recorder) = spawn_mock_backend().await;
    let (cartorio_url, _cartorio_state) = spawn_cartorio_server().await;
    let lacre_url = spawn_lacre(cartorio_url.clone(), backend_url.clone(), ORG).await;

    let known_body: &[u8] = b"the-known-good-manifest-body";
    let known_digest = manifest_digest(known_body);
    let evil_body: &[u8] = b"some-malicious-bytes-with-different-hash-entirely";
    let evil_digest = manifest_digest(evil_body);

    // Seed cartorio directly with the known-good admission — would
    // normally come from tabeliao publish through the admit endpoint.
    let (state, evt) = admitted_artifact(&known_digest, ORG, "good-image");
    _cartorio_state.store.admit(state, evt).await;

    println!("─── topology ───────────────────────────────────────────────");
    println!("cartorio (in-memory):  {cartorio_url}");
    println!("lacre  (real router):  {lacre_url}");
    println!("backend (mock OCI-2):  {backend_url}");
    println!();
    println!("─── seeded admission ───────────────────────────────────────");
    println!("known-good manifest body sha256: {known_digest}");
    println!("                             (admitted in cartorio, status=Active)");
    println!("evil          manifest body sha256: {evil_digest}");
    println!("                             (NOT admitted; should be rejected)");
    println!();

    let client = reqwest::Client::new();

    // ── Attempt 1: legit push of the known-good body to its real digest URL.
    println!("─── transaction 1 — legit push ──────────────────────────────");
    let url1 = format!("{lacre_url}/v2/myorg/myimage/manifests/{known_digest}");
    println!(
        "PUT {url1}\nContent-Type: application/vnd.oci.image.manifest.v1+json\n(body: {} bytes — sha256 matches URL ref)",
        known_body.len()
    );
    let r1 = client
        .put(&url1)
        .header("content-type", "application/vnd.oci.image.manifest.v1+json")
        .body(known_body.to_vec())
        .send()
        .await
        .unwrap();
    println!("→ HTTP {}", r1.status().as_u16());
    let body1 = r1.text().await.unwrap();
    println!("→ response body: {body1}");
    println!();

    // ── Attempt 2: ADVERSARIAL — evil body, but URL claims the known digest.
    println!("─── transaction 2 — adversarial spoof ──────────────────────");
    let url2 = format!("{lacre_url}/v2/myorg/myimage/manifests/{known_digest}");
    println!(
        "PUT {url2}    ← URL still claims known-good digest\nContent-Type: application/vnd.oci.image.manifest.v1+json\n(body: {} bytes — but actual sha256 = {})",
        evil_body.len(),
        evil_digest
    );
    let r2 = client
        .put(&url2)
        .header("content-type", "application/vnd.oci.image.manifest.v1+json")
        .body(evil_body.to_vec())
        .send()
        .await
        .unwrap();
    let status = r2.status().as_u16();
    let body2 = r2.text().await.unwrap();
    println!("→ HTTP {status}");
    println!("→ response body:");
    for line in body2.lines() {
        println!("  {line}");
    }
    println!();

    // ── Verify backend never saw the evil bytes ────────────────────
    println!("─── backend evidence ────────────────────────────────────────");
    let recv = backend_recorder.received.lock().unwrap();
    let manifest_puts: Vec<_> = recv
        .iter()
        .filter(|(m, p, _)| m == "PUT" && p.contains("/manifests/"))
        .collect();
    println!(
        "backend received {} total PUT requests; {} were /manifests/ PUTs.",
        recv.iter().filter(|(m, _, _)| m == "PUT").count(),
        manifest_puts.len()
    );
    for (m, p, body) in manifest_puts.iter() {
        let body_digest = manifest_digest(body);
        println!("  {m} {p}");
        println!("    body sha256: {body_digest}");
        println!(
            "    body digest matches known-good: {}",
            body_digest == known_digest
        );
    }
    println!();

    // ── Assertions ─────────────────────────────────────────────────
    let evil_reached_backend = manifest_puts
        .iter()
        .any(|(_, _, body)| body.as_slice() == evil_body);
    assert_eq!(
        status, 403,
        "evil-byte attempt MUST 403 (got {status})"
    );
    assert!(
        !evil_reached_backend,
        "evil bytes MUST NOT reach backend (would be a wire-level bypass)"
    );

    println!("─── proof summary ───────────────────────────────────────────");
    println!("✓ Adversarial PUT returned HTTP 403 Forbidden.");
    println!("✓ Evil bytes did NOT reach the backend OCI registry.");
    println!("✓ Lacre hashes body bytes; URL reference is informational only.");
    println!("✓ Tamper guarantee: the URL reference cannot subvert the gate.");
    println!();
    println!("Plan goal #4 — closed.");
}

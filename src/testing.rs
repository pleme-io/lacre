//! Canonical test fixtures for lacre — the single source of truth
//! for the mock OCI backend + lacre HTTP-server spawner that previously
//! lived as identical copies across `tests/cartorio_integration.rs`
//! and `examples/evil_byte_demo.rs`.
//!
//! Always compiled. Pure-data + axum/tokio glue (lacre's existing
//! deps); release-LTO strips it from binaries that don't call it.
//!
//! Pairs with [`cartorio::testing`] for the cartorio side. Together
//! they let any consumer wire a real cartorio + real lacre + mock
//! OCI backend in <10 lines.
//!
//! Example:
//!
//! ```ignore
//! let (backend_url, recorder) = lacre::testing::spawn_mock_backend().await;
//! let (cartorio_url, cartorio_state) =
//!     cartorio::testing::spawn_cartorio_server().await;
//! let lacre_url = lacre::testing::spawn_lacre(
//!     cartorio_url, backend_url, "pleme-io",
//! ).await;
//! ```

use std::sync::{Arc, Mutex};

use axum::{Router, extract::Request, response::Response, routing::any};

use crate::routes::{AppState, router};
use crate::{Backend, HttpBackend, HttpCartorioClient};

/// Records every request the mock backend received. Use
/// `recorder.received.lock().unwrap()` to inspect after the test
/// runs its requests through lacre.
#[derive(Default)]
pub struct MockBackend {
    /// Tuples of `(method, path, body)`.
    pub received: Mutex<Vec<(String, String, Vec<u8>)>>,
}

/// Spawn an OCI-shaped mock backend on a random TCP port. Returns
/// `(base_url, recorder)`. Every request gets logged into
/// `recorder.received` and the backend always responds with HTTP 201
/// + `docker-content-digest: sha256:fake`.
///
/// Body limit: 4 MiB — matches lacre's default.
pub async fn spawn_mock_backend() -> (String, Arc<MockBackend>) {
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
                    .expect("MockBackend mutex poisoned")
                    .push((method, path, body.to_vec()));
                Response::builder()
                    .status(201)
                    .header("docker-content-digest", "sha256:fake")
                    .body(axum::body::Body::from("mock-backend-ok"))
                    .expect("static response body builds")
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind 127.0.0.1:0");
    let addr = listener.local_addr().expect("local_addr");
    let url = format!("http://{addr}");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (url, backend)
}

/// Spawn a real lacre HTTP server on a random TCP port. Wires it to
/// the supplied cartorio + backend URLs and the supplied org. Returns
/// the lacre base URL.
///
/// `max_manifest_bytes` is set to 4 MiB — matches lacre's default.
pub async fn spawn_lacre(cartorio_url: String, backend_url: String, org: &str) -> String {
    let cartorio_client = HttpCartorioClient::new(cartorio_url)
        .expect("HttpCartorioClient with valid base URL");
    let backend: Arc<dyn Backend> =
        Arc::new(HttpBackend::new(backend_url).expect("HttpBackend with valid base URL"));
    let state = Arc::new(AppState {
        cartorio: Arc::new(cartorio_client),
        backend,
        org: org.into(),
        max_manifest_bytes: 4 * 1024 * 1024,
    });
    let app = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind 127.0.0.1:0");
    let addr = listener.local_addr().expect("local_addr");
    let url = format!("http://{addr}");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    url
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mock backend MUST log every request with method + path +
    /// body. The recorder is the canonical verification surface for
    /// "did the wire-level request reach the backend?" — load-bearing
    /// for the lacre evil-byte 403 demonstration.
    #[tokio::test]
    async fn mock_backend_records_method_path_body() {
        let (url, rec) = spawn_mock_backend().await;
        let client = reqwest::Client::new();
        let r = client
            .post(format!("{url}/v2/foo/manifests/bar"))
            .body(b"hello".to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 201);
        let recv = rec.received.lock().unwrap();
        assert_eq!(recv.len(), 1);
        assert_eq!(recv[0].0, "POST");
        assert_eq!(recv[0].1, "/v2/foo/manifests/bar");
        assert_eq!(recv[0].2, b"hello");
    }

    /// `spawn_lacre` returns a base URL that responds to /health.
    #[tokio::test]
    async fn lacre_health_responds() {
        let (cartorio_url, _state) = cartorio::testing::spawn_cartorio_server().await;
        let (backend_url, _rec) = spawn_mock_backend().await;
        let lacre_url = spawn_lacre(cartorio_url, backend_url, "pleme-io").await;
        let r = reqwest::Client::new()
            .get(format!("{lacre_url}/health"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
    }
}

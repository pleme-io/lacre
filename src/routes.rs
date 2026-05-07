//! Axum routes wiring the OCI Distribution Spec surface.
//!
//! The only gated route is `PUT /v2/{name}/manifests/{ref}` (multi-
//! segment name). Everything else under `/v2/...` is a passthrough.

use std::sync::Arc;

use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::any,
};
use serde::Serialize;

use crate::backend::Backend;
use crate::cartorio_client::CartorioClient;
use crate::gate::{GateDecision, decide};

pub struct AppState {
    pub cartorio: Arc<dyn CartorioClient>,
    pub backend: Arc<dyn Backend>,
    pub org: String,
    pub max_manifest_bytes: usize,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", any(healthz))
        .route("/health", any(healthz))
        .route("/{*rest}", any(any_handler))
        .route("/", any(any_handler))
        .with_state(state)
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

#[derive(Debug, Serialize)]
struct OciError {
    errors: Vec<OciErrorDetail>,
}

#[derive(Debug, Serialize)]
struct OciErrorDetail {
    code: &'static str,
    message: String,
    detail: serde_json::Value,
}

fn deny_response(status: StatusCode, code: &'static str, message: String) -> Response {
    let body = OciError {
        errors: vec![OciErrorDetail {
            code,
            message,
            detail: serde_json::Value::Null,
        }],
    };
    (status, Json(body)).into_response()
}

async fn any_handler(
    State(state): State<Arc<AppState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = uri.path();
    let path_and_query = uri
        .path_and_query()
        .map_or_else(|| path.to_string(), std::string::ToString::to_string);

    // Distribution spec version check.
    if path == "/v2" || path == "/v2/" {
        return passthrough_or_500(&state, &method, &path_and_query, &headers, body).await;
    }
    // Anything not under /v2/ is not OCI-spec; refuse politely.
    if !path.starts_with("/v2/") {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }

    // Manifest PUT is the only gated path. Match
    //   PUT /v2/<name...>/manifests/<reference>
    // where <name> may contain slashes (e.g. "myorg/myimage").
    let is_manifest_put = method == Method::PUT && parse_manifest_path(path).is_some();
    if is_manifest_put {
        if body.len() > state.max_manifest_bytes {
            return deny_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "MANIFEST_INVALID",
                format!(
                    "manifest body {} bytes exceeds limit {}",
                    body.len(),
                    state.max_manifest_bytes
                ),
            );
        }
        match decide(&*state.cartorio, &state.org, &body).await {
            Ok(GateDecision::Allow { .. }) => {
                let content_type = headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("application/vnd.oci.image.manifest.v1+json");
                match state.backend.put_manifest(path, content_type, body).await {
                    Ok(resp) => bake_axum(resp),
                    Err(e) => deny_response(
                        StatusCode::BAD_GATEWAY,
                        "DENIED",
                        format!("backend error: {e}"),
                    ),
                }
            }
            Ok(GateDecision::Reject { digest, reason }) => deny_response(
                StatusCode::FORBIDDEN,
                "DENIED",
                format!("cartorio rejects digest {digest}: {reason}"),
            ),
            Err(e) => deny_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "DENIED",
                format!("cartorio unavailable: {e}"),
            ),
        }
    } else {
        passthrough_or_500(&state, &method, &path_and_query, &headers, body).await
    }
}

async fn passthrough_or_500(
    state: &Arc<AppState>,
    method: &Method,
    path_and_query: &str,
    headers: &HeaderMap,
    body: Bytes,
) -> Response {
    let header_pairs: Vec<(String, String)> = headers
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|s| (k.as_str().to_string(), s.to_string()))
        })
        .collect();
    match state
        .backend
        .passthrough(method.as_str(), path_and_query, &header_pairs, body)
        .await
    {
        Ok(resp) => bake_axum(resp),
        Err(e) => deny_response(
            StatusCode::BAD_GATEWAY,
            "DENIED",
            format!("backend error: {e}"),
        ),
    }
}

fn bake_axum(resp: crate::backend::BackendResponse) -> Response {
    let mut builder = Response::builder().status(resp.status);
    for (k, v) in &resp.headers {
        if matches!(
            k.to_ascii_lowercase().as_str(),
            "transfer-encoding" | "connection" | "content-length"
        ) {
            continue;
        }
        builder = builder.header(k, v);
    }
    builder
        .body(axum::body::Body::from(resp.body))
        .unwrap_or_else(|_| {
            (StatusCode::INTERNAL_SERVER_ERROR, "response build failed").into_response()
        })
}

/// Match `/v2/<name...>/manifests/<reference>` and return
/// `(name, reference)` if the path matches. Name can contain slashes;
/// we anchor on the literal `/manifests/` segment.
#[must_use]
pub fn parse_manifest_path(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("/v2/")?;
    let idx = rest.find("/manifests/")?;
    let name = &rest[..idx];
    let reference = &rest[idx + "/manifests/".len()..];
    if name.is_empty() || reference.is_empty() || reference.contains('/') {
        return None;
    }
    Some((name, reference))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_manifest_path() {
        let m = parse_manifest_path("/v2/myimage/manifests/v1.0.0");
        assert_eq!(m, Some(("myimage", "v1.0.0")));
    }

    #[test]
    fn parse_namespaced_manifest_path() {
        let m = parse_manifest_path("/v2/myorg/myimage/manifests/sha256:abcd");
        assert_eq!(m, Some(("myorg/myimage", "sha256:abcd")));
    }

    #[test]
    fn parse_deeply_namespaced_manifest_path() {
        let m = parse_manifest_path("/v2/a/b/c/d/manifests/v1");
        assert_eq!(m, Some(("a/b/c/d", "v1")));
    }

    #[test]
    fn rejects_blob_path() {
        assert_eq!(parse_manifest_path("/v2/myimage/blobs/sha256:abcd"), None);
    }

    #[test]
    fn rejects_v2_root() {
        assert_eq!(parse_manifest_path("/v2/"), None);
        assert_eq!(parse_manifest_path("/v2"), None);
    }

    #[test]
    fn rejects_manifest_with_subpath() {
        // reference cannot contain slashes — that would make it
        // ambiguous with name segments.
        assert_eq!(parse_manifest_path("/v2/myimage/manifests/v1/extra"), None);
    }

    #[test]
    fn rejects_paths_outside_v2() {
        assert_eq!(parse_manifest_path("/api/v1/foo"), None);
    }
}

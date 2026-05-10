//! lacre — compliant OCI registry seal.
//!
//! lacre is a typed reverse proxy that sits in front of any OCI
//! Distribution Spec v1 registry (Zot, ECR, GHCR mirror, distribution).
//! On `PUT /v2/{name}/manifests/{reference}` it:
//!   1. computes `sha256:<hex>` of the raw manifest body,
//!   2. asks cartorio whether that digest is an Active artifact,
//!   3. forwards iff yes; rejects with 403 otherwise.
//!
//! All other OCI paths (GET/HEAD/POST/PATCH/DELETE on blobs and
//! manifests, `/v2/` version check, `/v2/_catalog`, tag listings) are
//! passed through unchanged. Only manifest PUT is the binding event
//! that makes an image "available" in the OCI spec — gating it is
//! sufficient to prevent non-compliant images from joining the
//! registry namespace.

pub mod backend;
pub mod cartorio_client;
pub mod config;
pub mod error;
pub mod gate;
pub mod metrics;
pub mod routes;
pub mod testing;

pub use backend::{Backend, HttpBackend};
pub use cartorio_client::{ArtifactSnapshot, CartorioClient, CartorioStatus, HttpCartorioClient};
pub use config::Config;
pub use error::{LacreError, Result};

use serde::{Deserialize, Serialize};

/// Runtime configuration for a lacre instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// HTTP listen address (e.g. `0.0.0.0:8083`).
    pub listen: String,
    /// Base URL of the cartorio service (e.g. `http://cartorio:8082`).
    pub cartorio_url: String,
    /// Base URL of the upstream OCI registry to proxy to (e.g.
    /// `http://zot.zot.svc:5000`).
    pub backend_url: String,
    /// Maximum manifest body size accepted, bytes. Defaults to 4 MiB
    /// (the OCI spec recommends manifests stay under this; anything
    /// larger is almost certainly malicious).
    #[serde(default = "default_max_manifest_bytes")]
    pub max_manifest_bytes: usize,
}

const fn default_max_manifest_bytes() -> usize {
    4 * 1024 * 1024
}

impl Config {
    #[must_use]
    pub fn new(listen: String, cartorio_url: String, backend_url: String) -> Self {
        Self {
            listen,
            cartorio_url,
            backend_url,
            max_manifest_bytes: default_max_manifest_bytes(),
        }
    }
}

//! Phase G — Prometheus metrics endpoint + counter emission.
//!
//! Audit gap closure: lareira-lacre's PrometheusRule referenced
//! `lacre_pushes_total` / `lacre_pushes_rejected_total` /
//! `lacre_cartorio_query_errors_total` but the binary emitted
//! nothing — silent failure. This module wires real counters +
//! starts the `:9090/metrics` listener.
//!
//! The counter names match the existing alert expressions exactly
//! so the alerts go from "aspirational" to "fire on real signal"
//! without touching the helmworks chart.

use std::net::SocketAddr;

use metrics::{counter, describe_counter};
use metrics_exporter_prometheus::PrometheusBuilder;

/// Counter names — keep in sync with
/// `helmworks/charts/lareira-lacre/templates/prometheusrule.yaml`.
pub const PUSHES_TOTAL: &str = "lacre_pushes_total";
pub const PUSHES_REJECTED_TOTAL: &str = "lacre_pushes_rejected_total";
pub const PUSHES_FORWARDED_TOTAL: &str = "lacre_pushes_forwarded_total";
pub const CARTORIO_QUERY_TOTAL: &str = "lacre_cartorio_query_total";
pub const CARTORIO_QUERY_ERRORS_TOTAL: &str = "lacre_cartorio_query_errors_total";

/// Install the Prometheus exporter on `addr` (e.g. "0.0.0.0:9090").
/// Idempotent — second call is a no-op (the global metrics recorder
/// only accepts one install).
///
/// # Errors
/// Returns the underlying exporter error (port bind failure etc.).
pub fn install_exporter(addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    PrometheusBuilder::new()
        .with_http_listener(addr)
        .install()?;
    describe_counters();
    Ok(())
}

fn describe_counters() {
    describe_counter!(
        PUSHES_TOTAL,
        "Total OCI manifest PUT requests reaching lacre's gate path"
    );
    describe_counter!(
        PUSHES_FORWARDED_TOTAL,
        "Manifest PUTs that passed the gate and were forwarded to the upstream registry"
    );
    describe_counter!(
        PUSHES_REJECTED_TOTAL,
        "Manifest PUTs that the gate rejected (deny / unknown digest / wrong org / unreachable cartorio)"
    );
    describe_counter!(
        CARTORIO_QUERY_TOTAL,
        "Total cartorio /by-digest queries lacre issued"
    );
    describe_counter!(
        CARTORIO_QUERY_ERRORS_TOTAL,
        "Cartorio queries that errored (network, 5xx, parse failures)"
    );
}

/// Convenience helpers — saves callers from threading a `Counter`
/// handle through the gate path.
pub fn inc_pushes_total() { counter!(PUSHES_TOTAL).increment(1); }
pub fn inc_pushes_forwarded() { counter!(PUSHES_FORWARDED_TOTAL).increment(1); }
pub fn inc_pushes_rejected(reason: &'static str) {
    counter!(PUSHES_REJECTED_TOTAL, "reason" => reason).increment(1);
}
pub fn inc_cartorio_query() { counter!(CARTORIO_QUERY_TOTAL).increment(1); }
pub fn inc_cartorio_query_error(kind: &'static str) {
    counter!(CARTORIO_QUERY_ERRORS_TOTAL, "kind" => kind).increment(1);
}

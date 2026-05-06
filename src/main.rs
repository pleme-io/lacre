use std::sync::Arc;

use clap::Parser;
use lacre::routes::{AppState, router};
use lacre::{Backend, Config, HttpBackend, HttpCartorioClient};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(version, about = "lacre — compliant OCI registry seal")]
struct Args {
    /// Address to listen on.
    #[arg(long, env = "LACRE_LISTEN", default_value = "0.0.0.0:8083")]
    listen: String,

    /// Cartorio base URL.
    #[arg(long, env = "LACRE_CARTORIO_URL")]
    cartorio_url: String,

    /// Backend OCI registry base URL.
    #[arg(long, env = "LACRE_BACKEND_URL")]
    backend_url: String,

    /// Org this lacre instance gates for.
    #[arg(long, env = "LACRE_ORG")]
    org: String,
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    let args = Args::parse();
    let cfg = Config::new(args.listen.clone(), args.cartorio_url, args.backend_url);

    let cartorio = HttpCartorioClient::new(cfg.cartorio_url.clone())?;
    let backend: Arc<dyn Backend> = Arc::new(HttpBackend::new(cfg.backend_url.clone())?);
    let state = Arc::new(AppState {
        cartorio: Arc::new(cartorio),
        backend,
        org: args.org,
        max_manifest_bytes: cfg.max_manifest_bytes,
    });

    let app = router(state);
    let listener = tokio::net::TcpListener::bind(&cfg.listen).await?;
    tracing::info!(listen = %cfg.listen, "lacre listening");
    axum::serve(listener, app).await?;
    Ok(())
}

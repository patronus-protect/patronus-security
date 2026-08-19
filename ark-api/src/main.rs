mod auth;
mod config;
mod dto;
mod routes;
mod state;

use std::path::PathBuf;

use axum::extract::DefaultBodyLimit;
use axum::middleware;
use axum::routing::{get, post};
use axum::Router;
use clap::Parser;
use patronus_ark::{ExactCacheConfig, PersistentCacheConfig, SecurityGateway};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use crate::config::Config;
use crate::state::AppState;

#[derive(Parser)]
#[command(name = "ark-api")]
struct Args {
    /// Path to the YAML config file.
    #[arg(long, default_value = "/etc/ark-api/config.yaml")]
    config: PathBuf,
    /// Download and warm up configured model assets, then exit without
    /// serving. Used to bake assets into the Docker image at build time.
    #[arg(long)]
    warmup_only: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let config = Config::load(&args.config)?;
    tracing::info!(path = %args.config.display(), "loaded config");

    // `cache.dir` in the config is a directory (friendlier to configure/mount
    // than a bare file path); `PersistentCacheConfig::storage_location` wants
    // the redb database file itself, so append a fixed filename.
    let cache_config = ExactCacheConfig {
        persistent: config.cache_dir.clone().map(|dir| PersistentCacheConfig {
            storage_location: dir.join("decisions.redb"),
            write_mode: patronus_ark::CacheWriteMode::Async,
            write_behind: Default::default(),
            encryption: None,
        }),
        ..Default::default()
    };
    let mut gateway = SecurityGateway::try_with_download_categories_and_cache(
        config.categories.clone(),
        config.max_level,
        config.model_dir.clone(),
        config.download_files,
        None,
        cache_config,
    )?;
    gateway.warmup()?;

    if args.warmup_only {
        tracing::info!("warmup complete, exiting (--warmup-only)");
        return Ok(());
    }

    let bind = config.bind;
    let max_upload_bytes = config.max_upload_bytes;
    let state = AppState::new(config, gateway);

    let protected = Router::new()
        .route("/v1/scan", post(routes::scan::submit_scan))
        .route(
            "/v1/scan/:request_id/events",
            get(routes::scan::scan_events),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_api_key,
        ));

    let app = Router::new()
        .route("/healthz", get(routes::health::healthz))
        .route("/readyz", get(routes::health::readyz))
        .merge(protected)
        .layer(DefaultBodyLimit::max(max_upload_bytes))
        .layer(RequestBodyLimitLayer::new(max_upload_bytes))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    tracing::info!(%bind, "starting ark-api");
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

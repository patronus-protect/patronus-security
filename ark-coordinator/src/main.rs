// SPDX-License-Identifier: GPL-3.0-only
use std::{path::PathBuf, time::Duration};

use clap::Parser;

#[derive(Parser)]
#[command(name = "ark-coordinator")]
struct Args {
    #[arg(long, default_value = "/etc/ark-coordinator/config.yaml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let config = ark_coordinator::config::CoordinatorConfig::load(&Args::parse().config)?;
    let bind = config.server.bind;
    let drain_timeout = Duration::from_millis(
        config
            .gateway
            .drain_timeout_ms()
            .ok_or("coordinator drain timeout overflow")?,
    );
    let state = ark_coordinator::service::AppState::connect(config).await?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(%bind, "starting ark-coordinator");
    axum::serve(listener, ark_coordinator::service::router(state.clone()))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    if tokio::time::timeout(drain_timeout, state.wait_for_idle())
        .await
        .is_err()
    {
        tracing::warn!("coordinator shutdown deadline reached with scans still active");
    }
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c()
        .await
        .expect("install Ctrl-C handler");
}

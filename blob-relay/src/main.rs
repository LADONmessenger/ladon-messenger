//! Blob-relay binary entry point. See `lib.rs` for router construction.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ladon_blob_relay::{
    build_app,
    capability::Signer,
    config::Config,
    gc::spawn_gc,
    rate_limit::{ConcurrencyGate, IpLimiter},
    storage::BlobStorage,
    AppState,
};
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .with_writer(std::io::stderr)
        .init();

    let config = Config::from_env()?;

    // LADON_BLOB_PANIC=1 — emergency wipe before binding. Spec §11.
    if config.panic_wipe {
        info!("panic wipe requested — shredding data dir");
        let storage = BlobStorage::open(config.data_dir.clone(), &config.master_key)?;
        storage.wipe_everything()?;
        info!("panic wipe complete; exiting");
        return Ok(());
    }

    let storage = BlobStorage::open(config.data_dir.clone(), &config.master_key)?;
    let signer = Signer::load_or_create(&config.signing_key_path)?;
    remove_retired_auth_store(&config.retired_auth_secrets_path);

    let state = Arc::new(AppState {
        storage: storage.clone(),
        capability_signer: signer,
        ip_limiter: IpLimiter::new(Duration::from_secs(60), 600),
        ip_limiter_read: IpLimiter::new(Duration::from_secs(60), 1200),
        put_gate: ConcurrencyGate::new(256, 8),
        config,
    });

    let shutdown = Arc::new(tokio::sync::Notify::new());
    spawn_gc(Arc::new(storage), shutdown.clone());

    let app = build_app(state.clone());
    let addr: SocketAddr = state.config.bind_addr.parse()?;
    info!(%addr, "blob-relay listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;

    let serve = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    );

    let shutdown_signal = async {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut term = signal(SignalKind::terminate()).expect("signal");
            let mut intr = signal(SignalKind::interrupt()).expect("signal");
            tokio::select! {
                _ = term.recv() => info!("sigterm received"),
                _ = intr.recv() => info!("sigint received"),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
    };

    if let Err(e) = serve.with_graceful_shutdown(shutdown_signal).await {
        error!(?e, "server error");
    }
    shutdown.notify_waiters();
    Ok(())
}

/// Addendum A2 stage 1: the per-identity upload secrets are retired. Their
/// store listed the long-term key of every uploader ever provisioned
/// (scan F29), so it is overwritten with zeros and removed, not left behind.
/// The overwrite is best effort on copy-on-write or flash storage; removing
/// the file is what ends its use. A failure is logged and does not stop the
/// relay — nothing reads the file any more.
fn remove_retired_auth_store(path: &std::path::Path) {
    use std::io::Write;
    let Ok(meta) = std::fs::metadata(path) else { return };
    let overwrite = std::fs::OpenOptions::new().write(true).open(path).and_then(|mut f| {
        f.write_all(&vec![0u8; meta.len() as usize])?;
        f.sync_all()
    });
    if overwrite.is_err() {
        error!("retired upload-identity store: overwrite failed");
    }
    match std::fs::remove_file(path) {
        Ok(()) => info!("retired upload-identity store removed"),
        Err(_) => error!("retired upload-identity store: removal failed"),
    }
}

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use cortex_server::{build_router, config::AppConfig, db, state::AppState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "cortex_server=info,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = AppConfig::from_env()?;
    let pool = db::create_pool(&config.database_url).await?;
    db::run_migrations(&pool).await?;

    // Daily cleanup: remove audit logs older than 60 days
    let cleanup_pool = pool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(86400));
        loop {
            interval.tick().await;
            match sqlx::query(
                "DELETE FROM audit_logs WHERE timestamp < datetime('now', '-60 days')",
            )
            .execute(&cleanup_pool)
            .await
            {
                Ok(r) => tracing::info!("Audit log cleanup: {} rows deleted", r.rows_affected()),
                Err(e) => tracing::warn!("Audit log cleanup failed: {}", e),
            }
        }
    });

    let state = AppState::new(pool, config.clone());
    let app = build_router(state);
    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));

    if let (Some(cert_file), Some(key_file)) = (&config.tls_cert_file, &config.tls_key_file) {
        serve_tls(app, addr, cert_file, key_file).await?;
    } else {
        tracing::info!("CortexAuth server listening on http://{}", addr);
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;
    }

    Ok(())
}

async fn serve_tls(
    app: axum::Router,
    addr: SocketAddr,
    cert_file: &str,
    key_file: &str,
) -> anyhow::Result<()> {
    use hyper::server::conn::http1;
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;
    use tokio_rustls::rustls::{self, Certificate, PrivateKey};
    use tokio_rustls::TlsAcceptor;
    use tower::Service;

    let cert_bytes = std::fs::read(cert_file)?;
    let key_bytes = std::fs::read(key_file)?;

    let certs: Vec<Certificate> = rustls_pemfile::certs(&mut cert_bytes.as_ref())
        .map_err(|e| anyhow::anyhow!("cert parse error: {}", e))?
        .into_iter()
        .map(Certificate)
        .collect();

    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut key_bytes.as_ref())
        .map_err(|e| anyhow::anyhow!("key parse error: {}", e))?;

    anyhow::ensure!(!keys.is_empty(), "No PKCS8 private key found in {}", key_file);

    let tls_config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, PrivateKey(keys.remove(0)))
        .map_err(|e| anyhow::anyhow!("TLS config error: {}", e))?;

    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("CortexAuth server listening on https://{}", addr);

    loop {
        let (tcp, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let app = app.clone();

        tokio::spawn(async move {
            let tls = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("TLS handshake failed from {}: {}", peer, e);
                    return;
                }
            };

            let svc =
                hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let (parts, body) = req.into_parts();
                    let req =
                        hyper::Request::from_parts(parts, axum::body::Body::new(body));
                    let mut app = app.clone();
                    async move { app.call(req).await }
                });

            if let Err(e) = http1::Builder::new()
                .serve_connection(TokioIo::new(tls), svc)
                .with_upgrades()
                .await
            {
                tracing::warn!("HTTP connection error from {}: {}", peer, e);
            }
        });
    }
}

//! Remotier's sync server.
//!
//! Stores opaque encrypted records and routes them between a user's devices, and between
//! the members of a shared group. It cannot read any of them: see the crate docs of
//! `remotier-sync-proto` for what it can and cannot see.

mod auth;
mod config;
mod error;
mod ratelimit;
mod routes;
mod state;
mod store;

use std::sync::Arc;

use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use crate::config::Config;
use crate::state::AppState;
use crate::store::{postgres::PostgresStore, sqlite::SqliteStore, Store};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // `--health-check` asks the running server whether it is answering, and is what the
    // image's HEALTHCHECK runs. The image ships no curl or wget on purpose, so the binary
    // has to be able to check itself.
    if std::env::args().any(|arg| arg == "--health-check") {
        return match health_check() {
            Ok(()) => Ok(()),
            Err(e) => {
                eprintln!("unhealthy: {e}");
                std::process::exit(1);
            }
        };
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "remotier_sync_server=info,tower_http=warn".into()),
        )
        .init();

    let config = Config::from_env()?;

    // The URL scheme picks the backend. SQLite is the self-host default: one binary, one
    // file. Postgres is what the hosted instance runs.
    let store: Arc<dyn Store> = if config.database_url.starts_with("postgres") {
        Arc::new(PostgresStore::connect(&config.database_url).await?)
    } else {
        Arc::new(SqliteStore::connect(&config.database_url).await?)
    };
    store.migrate().await?;

    let state = AppState {
        store,
        config: Arc::new(config.clone()),
        auth_limit: Arc::new(crate::ratelimit::RateLimit::new(
            10,
            std::time::Duration::from_secs(60),
        )),
    };

    let app = routes::router(state)
        .layer(RequestBodyLimitLayer::new(16 * 1024 * 1024))
        .layer(TraceLayer::new_for_http())
        // ConnectInfo so the rate limiter can see a peer address. Behind a reverse proxy
        // that is the proxy's address, which is why the limiter is a speed bump and not
        // the only thing between an attacker and the password endpoint.
        .into_make_service_with_connect_info::<std::net::SocketAddr>();

    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    tracing::info!(
        bind = %config.bind,
        registration_open = config.registration_open,
        "remotier sync listening"
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}

/// Ask the local server for `/v1/instance` and insist on a 200.
///
/// Hand-rolled over `TcpStream` rather than through an HTTP client: the server needs no
/// outbound HTTP otherwise, and pulling a client library in for a liveness probe would
/// add a TLS stack to a binary whose dependency graph is deliberately small.
fn health_check() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read as _, Write as _};
    use std::net::TcpStream;
    use std::time::Duration;

    let bind = std::env::var("REMOTIER_BIND").unwrap_or_else(|_| "0.0.0.0:8787".into());
    // 0.0.0.0 means "every interface" to a listener and is not a usable destination on
    // every platform, so the probe dials loopback on the same port.
    let port = bind.rsplit(':').next().unwrap_or("8787");
    let address = format!("127.0.0.1:{port}");

    let mut stream = TcpStream::connect(&address)?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    write!(
        stream,
        "GET /v1/instance HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
    )?;

    let mut response = String::new();
    // Only the status line matters, but the body is small and reading to the close is
    // simpler than parsing a length.
    stream.take(4096).read_to_string(&mut response)?;

    if response.starts_with("HTTP/1.1 200") {
        Ok(())
    } else {
        Err(format!(
            "unexpected response: {}",
            response.lines().next().unwrap_or("")
        )
        .into())
    }
}

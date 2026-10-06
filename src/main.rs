mod audit;
mod config;
mod identity;
mod policy;
mod proxy;
mod tls;

use arc_swap::ArcSwap;
use config::Config;
use http_body_util::Full;
use hyper::{
    body::{Bytes, Incoming},
    service::service_fn,
    Request, Response, StatusCode,
};
use hyper_util::{
    client::legacy::Client,
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
use proxy::Proxy;
use serde_json::json;
use std::{
    convert::Infallible,
    error::Error,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{net::TcpListener, sync::{watch, Semaphore}, task::JoinSet};
use tokio_rustls::TlsAcceptor;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("fatal: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    let cfg = Config::from_env()?;
    let policy = policy::PolicyEngine::load(&cfg.policy_file)?;
    let tls_store: tls::SharedTlsConfig =
        Arc::new(ArcSwap::from_pointee(tls::build_server_config(&cfg.tls)?));
    tokio::spawn(tls::reload_loop(cfg.tls.clone(), tls_store.clone(), cfg.reload_interval));

    let proxy = Arc::new(Proxy {
        policy,
        upstream: cfg.upstream.clone(),
        client: Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(30))
            .build_http(),
        limiter: Arc::new(Semaphore::new(cfg.max_concurrency)),
        max_body_bytes: cfg.max_body_bytes,
        upstream_timeout: cfg.upstream_timeout,
    });

    // Health/readiness on a separate plain-HTTP port (for orchestrators, no client cert).
    let ready = Arc::new(AtomicBool::new(true));
    tokio::spawn(admin_server(cfg.admin_listen, ready.clone()));

    let listener = TcpListener::bind(cfg.listen).await?;
    audit::log("started", &format!("listening on {} -> {}", cfg.listen, cfg.upstream));

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut connections = JoinSet::new();
    let mut stop = Box::pin(shutdown_signal());

    loop {
        tokio::select! {
            _ = &mut stop => break,
            Some(_) = connections.join_next(), if !connections.is_empty() => {} // reap finished
            accepted = listener.accept() => {
                let Ok((tcp, peer)) = accepted else { continue };
                // New connections always use the *current* TLS/trust config.
                let acceptor = TlsAcceptor::from(tls_store.load_full());
                connections.spawn(serve_connection(
                    acceptor, tcp, peer, proxy.clone(), shutdown_rx.clone(),
                ));
            }
        }
    }

    // Graceful shutdown: fail readiness, stop accepting, let in-flight requests finish.
    ready.store(false, Ordering::Relaxed);
    audit::log("shutdown", "draining connections (max 30s)");
    let _ = shutdown_tx.send(true);
    drop(listener);
    let drain = async { while connections.join_next().await.is_some() {} };
    let _ = tokio::time::timeout(Duration::from_secs(30), drain).await;
    Ok(())
}

async fn serve_connection(
    acceptor: TlsAcceptor,
    tcp: tokio::net::TcpStream,
    peer: SocketAddr,
    proxy: Arc<Proxy>,
    mut shutdown: watch::Receiver<bool>,
) {
    // TLS layer: handshake fails here if the client cert is missing, expired, not yet
    // valid, or not chained to the (current) trusted CA bundle.
    let tls = match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => {
            audit::emit(json!({
                "ts_ms": audit::now_ms(), "event": "tls_handshake_failed",
                "peer": peer.ip().to_string(), "decision": "DENY", "error": e.to_string(),
            }));
            return;
        }
        Err(_) => return,
    };

    // Application layer: derive + validate the identity from the verified leaf cert.
    let identity = Arc::new(match tls.get_ref().1.peer_certificates() {
        Some(chain) => identity::extract(chain),
        None => Err("no client certificate".to_string()),
    });
    if let Ok(cert) = &*identity {
        audit::emit(json!({
            "ts_ms": audit::now_ms(), "event": "client_authenticated", "identity": cert.identity,
            "subject": cert.subject, "issuer": cert.issuer, "serial": cert.serial,
            "not_before": cert.not_before, "not_after": cert.not_after,
            "uri_sans": cert.uri_sans, "dns_sans": cert.dns_sans, "chain_len": cert.chain_len,
            "trust": "chain verified by TLS layer",
        }));
    }

    let service = service_fn(move |req| proxy.clone().handle(peer, identity.clone(), req));
    let builder = auto::Builder::new(TokioExecutor::new()); // HTTP/1.1 or HTTP/2 via ALPN
    let conn = builder.serve_connection(TokioIo::new(tls), service);
    tokio::pin!(conn);
    tokio::select! {
        _ = conn.as_mut() => {}
        _ = shutdown.changed() => {
            conn.as_mut().graceful_shutdown(); // finish in-flight requests, then close
            let _ = conn.await;
        }
    }
}

async fn shutdown_signal() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

async fn admin_server(addr: SocketAddr, ready: Arc<AtomicBool>) {
    let Ok(listener) = TcpListener::bind(addr).await else {
        eprintln!("fatal: cannot bind admin address {addr}");
        std::process::exit(1);
    };
    loop {
        let Ok((tcp, _)) = listener.accept().await else { continue };
        let ready = ready.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req: Request<Incoming>| {
                let (status, body) = match req.uri().path() {
                    "/healthz" => (StatusCode::OK, "ok\n"),
                    "/readyz" if ready.load(Ordering::Relaxed) => (StatusCode::OK, "ready\n"),
                    "/readyz" => (StatusCode::SERVICE_UNAVAILABLE, "shutting down\n"),
                    _ => (StatusCode::NOT_FOUND, "not found\n"),
                };
                let mut resp = Response::new(Full::new(Bytes::from(body)));
                *resp.status_mut() = status;
                async move { Ok::<_, Infallible>(resp) }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(tcp), service)
                .await;
        });
    }
}

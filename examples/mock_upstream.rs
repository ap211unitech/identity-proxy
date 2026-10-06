//! Tiny upstream for testing: echoes method, path and the headers the proxy added.
//! Run: cargo run --release --example mock_upstream   (listens on 127.0.0.1:8080)

use http_body_util::Full;
use hyper::{body::Bytes, service::service_fn, Request, Response};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    let addr = std::env::var("MOCK_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let listener = TcpListener::bind(&addr).await.unwrap();
    println!("mock upstream on http://{addr}");
    loop {
        let (tcp, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            let service = service_fn(|req: Request<hyper::body::Incoming>| async move {
                let header = |n: &str| {
                    req.headers().get(n).and_then(|v| v.to_str().ok()).unwrap_or("").to_string()
                };
                let body = serde_json::json!({
                    "method": req.method().as_str(),
                    "uri": req.uri().to_string(),
                    "host": header("host"),
                    "x-forwarded-for": header("x-forwarded-for"),
                    "x-forwarded-proto": header("x-forwarded-proto"),
                    "x-forwarded-host": header("x-forwarded-host"),
                    "x-authenticated-identity": header("x-authenticated-identity"),
                    "via": header("via"),
                    "x-request-id": header("x-request-id"),
                });
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(body.to_string()))))
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(tcp), service)
                .await;
        });
    }
}

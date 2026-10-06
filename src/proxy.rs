//! Request pipeline: Intercept -> Identify -> Authorize -> Observe -> forward.

use crate::{
    audit,
    identity::CertInfo,
    policy::{self, PolicyEngine},
};
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Full, LengthLimitError, Limited};
use hyper::{
    body::{Bytes, Incoming},
    header::{self, HeaderMap, HeaderName, HeaderValue},
    Request, Response, StatusCode, Uri, Version,
};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use serde_json::json;
use std::{
    convert::Infallible,
    error::Error,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;

pub type BoxError = Box<dyn Error + Send + Sync>;
pub type Body = UnsyncBoxBody<Bytes, BoxError>;

/// Token we add to `Via`; seeing it on an inbound request means we are in a loop.
const VIA_TOKEN: &str = "identity-proxy";

const HOP_BY_HOP: [&str; 9] = [
    "connection", "proxy-connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade",
];

/// Headers that only this proxy is allowed to set (client-supplied values are dropped).
const PROXY_OWNED: [&str; 8] = [
    "host", "forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
    "x-forwarded-port", "x-authenticated-identity", "x-request-id",
];

pub struct Proxy {
    pub policy: PolicyEngine,
    pub upstream: String, // "http://host:port"
    pub client: Client<HttpConnector, Body>,
    pub limiter: Arc<Semaphore>,
    pub max_body_bytes: usize,
    pub upstream_timeout: Duration,
}

struct Outcome {
    response: Response<Body>,
    decision: &'static str, // ALLOW / DENY (authorization decision)
    reason: &'static str,
    upstream_status: Option<u16>,
}

impl Outcome {
    fn local(status: StatusCode, decision: &'static str, reason: &'static str) -> Self {
        let body = Full::new(Bytes::from(format!("{} {}\n", status.as_u16(), reason)))
            .map_err(|never| match never {})
            .boxed_unsync();
        let mut response = Response::new(body);
        *response.status_mut() = status;
        Outcome { response, decision, reason, upstream_status: None }
    }
}

impl Proxy {
    /// Entry point per request: runs the pipeline, then writes the audit event.
    pub async fn handle(
        self: Arc<Self>,
        peer: SocketAddr,
        identity: Arc<Result<CertInfo, String>>,
        req: Request<Incoming>,
    ) -> Result<Response<Body>, Infallible> {
        let start = Instant::now();
        let request_id = request_id(req.headers());
        let method = req.method().to_string();
        let path = req.uri().path().to_string(); // query string is intentionally not logged
        let host = request_host(&req);
        let safe_headers = audit::safe_headers(req.headers());
        let who = match &*identity {
            Ok(cert) => cert.identity.clone(),
            Err(_) => "unauthenticated".to_string(),
        };

        let mut outcome = self.process(peer, &identity, &host, &request_id, req).await;
        set_header(outcome.response.headers_mut(), "x-request-id", &request_id);

        audit::emit(json!({
            "ts_ms": audit::now_ms(),
            "request_id": request_id,
            "identity": who,
            "peer": peer.ip().to_string(),
            "method": method,
            "host": host,
            "path": path,
            "headers": safe_headers,
            "decision": outcome.decision,
            "reason": outcome.reason,
            "status": outcome.response.status().as_u16(),
            "upstream_status": outcome.upstream_status,
            // Time until response headers are ready; body streaming is not included.
            "latency_ms": start.elapsed().as_millis() as u64,
        }));
        Ok(outcome.response)
    }

    async fn process(
        &self,
        peer: SocketAddr,
        identity: &Result<CertInfo, String>,
        host: &str,
        request_id: &str,
        req: Request<Incoming>,
    ) -> Outcome {
        use StatusCode as S;

        // Identify: TLS already did chain/expiry checks; this is the identity-shape check.
        let cert = match identity {
            Ok(cert) => cert,
            Err(_) => return Outcome::local(S::UNAUTHORIZED, "DENY", "invalid_client_identity"),
        };

        // Loop prevention.
        let looped = req.headers().get_all(header::VIA).iter().any(|v| {
            v.to_str().map(|s| s.contains(VIA_TOKEN)).unwrap_or(false)
        });
        if looped {
            return Outcome::local(S::LOOP_DETECTED, "DENY", "proxy_loop");
        }

        // Authorize: reject ambiguous paths first, then check policy (default deny).
        if !policy::is_safe_path(req.uri().path()) {
            return Outcome::local(S::BAD_REQUEST, "DENY", "ambiguous_path");
        }
        if !self.policy.is_allowed(&cert.identity, req.method().as_str(), req.uri().path()) {
            return Outcome::local(S::FORBIDDEN, "DENY", "no_matching_rule");
        }

        // Resilience: concurrency limit (load shedding) and body limit.
        let _permit = match self.limiter.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => return Outcome::local(S::SERVICE_UNAVAILABLE, "ALLOW", "overloaded"),
        };
        let declared_len = req
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok());
        if declared_len.is_some_and(|len| len > self.max_body_bytes) {
            return Outcome::local(S::PAYLOAD_TOO_LARGE, "ALLOW", "body_too_large");
        }

        // Build the upstream request. The body is streamed (never buffered); for chunked
        // uploads the limit is enforced while streaming.
        let (mut parts, body) = req.into_parts();
        let path_and_query = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let uri: Uri = match format!("{}{}", self.upstream, path_and_query).parse() {
            Ok(uri) => uri,
            Err(_) => return Outcome::local(S::BAD_REQUEST, "ALLOW", "bad_uri"),
        };
        prepare_request_headers(&mut parts.headers, peer, host, &cert.identity, request_id);
        parts.uri = uri;
        parts.version = Version::HTTP_11; // upstream leg is always HTTP/1.1

        let too_big = Arc::new(AtomicBool::new(false));
        let flag = too_big.clone();
        let body = Limited::new(body, self.max_body_bytes)
            .map_err(move |e: BoxError| {
                if e.is::<LengthLimitError>() {
                    flag.store(true, Ordering::Relaxed);
                }
                e
            })
            .boxed_unsync();

        // Forward, with an upstream timeout (covers connect + time to response headers).
        let upstream_req = Request::from_parts(parts, body);
        match tokio::time::timeout(self.upstream_timeout, self.client.request(upstream_req)).await {
            Err(_) => Outcome::local(S::GATEWAY_TIMEOUT, "ALLOW", "upstream_timeout"),
            Ok(Err(_)) if too_big.load(Ordering::Relaxed) => {
                Outcome::local(S::PAYLOAD_TOO_LARGE, "ALLOW", "body_too_large")
            }
            Ok(Err(e)) => {
                audit::log("upstream_error", &format!("{request_id}: {e}"));
                Outcome::local(S::BAD_GATEWAY, "ALLOW", "upstream_error")
            }
            Ok(Ok(resp)) => {
                let (mut parts, body) = resp.into_parts();
                strip_hop_by_hop(&mut parts.headers);
                let status = parts.status;
                let body = body.map_err(|e| -> BoxError { Box::new(e) }).boxed_unsync();
                Outcome {
                    response: Response::from_parts(parts, body),
                    decision: "ALLOW",
                    reason: "policy",
                    upstream_status: Some(status.as_u16()),
                }
            }
        }
    }
}

/// Propagate a sane inbound X-Request-Id, otherwise generate one.
fn request_id(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|v| {
            !v.is_empty()
                && v.len() <= 64
                && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
        .map(str::to_owned)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
}

/// HTTP/1.1 sends `Host`, HTTP/2 sends `:authority` (exposed as the URI authority).
fn request_host<B>(req: &Request<B>) -> String {
    req.headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .or_else(|| req.uri().authority().map(|a| a.to_string()))
        .unwrap_or_default()
}

fn set_header(headers: &mut HeaderMap, name: &'static str, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.insert(HeaderName::from_static(name), value);
    }
}

/// Remove hop-by-hop headers, including any header named by `Connection: ...`.
fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let named_by_connection: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect();
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
    for name in named_by_connection {
        headers.remove(name);
    }
}

/// Deliberate header handling for the upstream request:
///  * hop-by-hop headers removed;
///  * client-supplied Forwarded / X-Forwarded-* / identity / request-id headers are dropped
///    (the client is not a trusted proxy) and replaced with values we know to be true;
///  * `Host` is dropped so the HTTP client sets the upstream's authority; the original
///    host goes into X-Forwarded-Host;
///  * `Via` gets our token appended (used for loop detection).
fn prepare_request_headers(
    headers: &mut HeaderMap,
    peer: SocketAddr,
    host: &str,
    identity: &str,
    request_id: &str,
) {
    strip_hop_by_hop(headers);
    let via = {
        let previous: Vec<&str> = headers
            .get_all(header::VIA)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        previous.iter().chain([&format!("1.1 {VIA_TOKEN}").as_str()]).copied().collect::<Vec<_>>().join(", ")
    };
    for name in PROXY_OWNED {
        headers.remove(name);
    }
    set_header(headers, "x-forwarded-for", &peer.ip().to_string());
    set_header(headers, "x-forwarded-host", host);
    set_header(headers, "x-forwarded-proto", "https");
    set_header(headers, "x-authenticated-identity", identity);
    set_header(headers, "x-request-id", request_id);
    set_header(headers, "via", &via);
}

use hyper::HeaderMap;
use serde_json::{json, Map, Value};
use std::time::{SystemTime, UNIX_EPOCH};

const SAFE_HEADERS: [&str; 4] = ["user-agent", "content-type", "content-length", "accept"];

pub fn safe_headers(headers: &HeaderMap) -> Value {
    let mut out = Map::new();
    for name in SAFE_HEADERS {
        if let Some(v) = headers.get(name).and_then(|v| v.to_str().ok()) {
            out.insert(name.into(), Value::String(v.chars().take(200).collect()));
        }
    }
    Value::Object(out)
}

pub fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

pub fn emit(event: Value) {
    println!("{event}");
}

/// Operational (non-request) log line.
pub fn log(event: &str, detail: &str) {
    emit(json!({ "ts_ms": now_ms(), "event": event, "detail": detail }));
}

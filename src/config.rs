use std::{net::SocketAddr, time::Duration};

#[derive(Clone)]
pub struct TlsPaths {
    pub cert: String,
    pub key: String,
    pub client_ca: String,
}

pub struct Config {
    pub listen: SocketAddr,
    pub admin_listen: SocketAddr,
    pub upstream: String,
    pub tls: TlsPaths,
    pub policy_file: String,
    pub max_body_bytes: usize,
    pub upstream_timeout: Duration,
    pub max_concurrency: usize,
    pub reload_interval: Duration,
}

fn env(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn parse<T: std::str::FromStr>(name: &str, default: &str) -> Result<T, String> {
    env(name, default)
        .parse()
        .map_err(|_| format!("invalid value for {name}"))
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        Ok(Config {
            listen: parse("LISTEN_ADDR", "0.0.0.0:8443")?,
            admin_listen: parse("ADMIN_ADDR", "0.0.0.0:8081")?,
            upstream: parse_upstream(&env("UPSTREAM_URL", "http://backend:8080"))?,
            tls: TlsPaths {
                cert: env("TLS_CERT", "/etc/proxy/server.pem"),
                key: env("TLS_KEY", "/etc/proxy/server.key"),
                client_ca: env("CLIENT_CA", "/etc/proxy/client-ca.pem"),
            },
            policy_file: env("POLICY_FILE", "/etc/proxy/policy.yaml"),
            max_body_bytes: parse("MAX_BODY_BYTES", "1048576")?,
            upstream_timeout: Duration::from_secs(parse("UPSTREAM_TIMEOUT_SECS", "10")?),
            max_concurrency: parse("MAX_CONCURRENCY", "1024")?,
            reload_interval: Duration::from_secs(parse("RELOAD_INTERVAL_SECS", "5")?),
        })
    }
}

/// Only plain `http://host:port` upstreams are supported
fn parse_upstream(raw: &str) -> Result<String, String> {
    let uri: hyper::Uri = raw.parse().map_err(|_| "UPSTREAM_URL is not a valid URL")?;
    if uri.scheme_str() != Some("http") {
        return Err("UPSTREAM_URL must use http://".into());
    }
    let authority = uri.authority().ok_or("UPSTREAM_URL has no host")?;
    if !matches!(uri.path(), "" | "/") || uri.query().is_some() {
        return Err("UPSTREAM_URL must not contain a path or query".into());
    }
    Ok(format!("http://{authority}"))
}

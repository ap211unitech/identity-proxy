//! TLS server config + hot-reloadable trust store.
//!
//! The client-certificate verifier (rustls `WebPkiClientVerifier`) lives inside the
//! `ServerConfig`. Reloading the CA bundle = building a new `ServerConfig` and
//! atomically swapping it in; each new connection picks up whatever is current.

use crate::{audit, config::TlsPaths};
use arc_swap::ArcSwap;
use rustls::{
    pki_types::CertificateDer, server::WebPkiClientVerifier, RootCertStore, ServerConfig,
};
use std::{
    collections::hash_map::DefaultHasher,
    fs::File,
    hash::{Hash, Hasher},
    io::BufReader,
    sync::Arc,
    time::Duration,
};

pub type SharedTlsConfig = Arc<ArcSwap<ServerConfig>>;

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let file = File::open(path).map_err(|e| format!("{path}: {e}"))?;
    rustls_pemfile::certs(&mut BufReader::new(file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{path}: {e}"))
}

/// Build a complete TLS config from files. Any problem is an error, so a bad
/// update can never replace a working config.
pub fn build_server_config(paths: &TlsPaths) -> Result<ServerConfig, String> {
    let chain = load_certs(&paths.cert)?;
    if chain.is_empty() {
        return Err(format!("{}: no certificates found", paths.cert));
    }
    let key_file = File::open(&paths.key).map_err(|e| format!("{}: {e}", paths.key))?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))
        .map_err(|e| format!("{}: {e}", paths.key))?
        .ok_or_else(|| format!("{}: no private key found", paths.key))?;

    // Trust anchors for *client* certificates. Strict: one unparsable cert rejects the bundle.
    let mut roots = RootCertStore::empty();
    let (added, ignored) = roots.add_parsable_certificates(load_certs(&paths.client_ca)?);
    if added == 0 || ignored > 0 {
        return Err(format!(
            "{}: {added} usable CA certs, {ignored} unparsable",
            paths.client_ca
        ));
    }

    // Default verifier REQUIRES a client cert and validates chain, signatures,
    // validity period and the clientAuth EKU.
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| e.to_string())?;

    let mut config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .map_err(|e| e.to_string())?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

/// Fingerprint of all TLS input files (None if any is unreadable, e.g. mid-update).
fn fingerprint(paths: &TlsPaths) -> Option<u64> {
    let mut hasher = DefaultHasher::new();
    for p in [&paths.cert, &paths.key, &paths.client_ca] {
        std::fs::read(p).ok()?.hash(&mut hasher);
    }
    Some(hasher.finish())
}

/// Poll the files; when they change, validate by building a new config and swap it in.
/// On failure the previous config stays active (this *is* the rollback).
pub async fn reload_loop(paths: TlsPaths, store: SharedTlsConfig, every: Duration) {
    let mut last = fingerprint(&paths);
    loop {
        tokio::time::sleep(every).await;
        let current = fingerprint(&paths);
        if current == last {
            continue;
        }
        last = current;
        match build_server_config(&paths) {
            Ok(cfg) => {
                store.store(Arc::new(cfg));
                audit::log("trust_reload_ok", "new TLS/trust config active for new connections");
            }
            Err(e) => audit::log("trust_reload_rejected", &format!("keeping previous config: {e}")),
        }
    }
}

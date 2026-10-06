//! Application-layer client identity extraction (runs after the TLS handshake succeeded).
//!
//! rustls already verified: chain -> trusted CA, signatures, validity period, clientAuth EKU.
//! Here we parse the leaf, re-check validity (defence in depth), and derive the identity.

use rustls::pki_types::CertificateDer;
use x509_parser::{extensions::GeneralName, prelude::*};

#[derive(Debug)]
pub struct CertInfo {
    /// The authenticated NHI identity used for authorization.
    pub identity: String,
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: i64, // unix seconds
    pub not_after: i64,
    pub uri_sans: Vec<String>,
    pub dns_sans: Vec<String>,
    pub chain_len: usize,
}

pub fn extract(chain: &[CertificateDer<'_>]) -> Result<CertInfo, String> {
    let leaf = chain.first().ok_or("no client certificate")?;
    let (_, cert) = X509Certificate::from_der(leaf).map_err(|e| format!("bad certificate: {e}"))?;

    if !cert.validity().is_valid() {
        return Err("certificate expired or not yet valid".into());
    }

    let mut uri_sans = Vec::new();
    let mut dns_sans = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            match name {
                GeneralName::URI(u) => uri_sans.push(u.to_string()),
                GeneralName::DNSName(d) => dns_sans.push(d.to_string()),
                _ => {}
            }
        }
    }

    // Identity: a SPIFFE URI SAN if present (exactly one, strictly validated),
    // otherwise the first DNS SAN (prefixed "dns:"). Anything else is rejected.
    let spiffe: Vec<&String> = uri_sans.iter().filter(|u| u.starts_with("spiffe:")).collect();
    let identity = match spiffe.as_slice() {
        [one] => {
            validate_spiffe(one)?;
            (*one).clone()
        }
        [] => match dns_sans.first() {
            Some(dns) => format!("dns:{dns}"),
            None => return Err("certificate has no SPIFFE URI SAN or DNS SAN".into()),
        },
        _ => return Err("certificate has multiple SPIFFE URI SANs".into()),
    };

    Ok(CertInfo {
        identity,
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        serial: cert.raw_serial_as_string(),
        not_before: cert.validity().not_before.timestamp(),
        not_after: cert.validity().not_after.timestamp(),
        uri_sans,
        dns_sans,
        chain_len: chain.len(),
    })
}

/// spiffe://<trust-domain>/<path>: lowercase scheme, no userinfo/port/query/fragment,
/// non-empty trust domain, at least one path segment, no empty/"."/".." segments.
fn validate_spiffe(id: &str) -> Result<(), String> {
    let bad = |why: &str| Err(format!("malformed SPIFFE ID ({why}): {id}"));
    let rest = match id.strip_prefix("spiffe://") {
        Some(r) if id.len() <= 2048 => r,
        _ => return bad("scheme or length"),
    };
    let (domain, path) = match rest.split_once('/') {
        Some(parts) => parts,
        None => return bad("missing path"),
    };
    let domain_ok = !domain.is_empty()
        && domain.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-._".contains(&b));
    if !domain_ok {
        return bad("trust domain");
    }
    let segment_ok = |s: &str| {
        !s.is_empty()
            && s != "."
            && s != ".."
            && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
    };
    if !path.split('/').all(segment_ok) {
        return bad("path");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_spiffe;

    #[test]
    fn accepts_valid_ids() {
        assert!(validate_spiffe("spiffe://acme/prod/payment-agent").is_ok());
        assert!(validate_spiffe("spiffe://customer-a.example.org/a/b_c").is_ok());
    }

    #[test]
    fn rejects_malformed_ids() {
        for id in [
            "spiffe://acme",                 // no path
            "spiffe:///prod/x",              // empty trust domain
            "spiffe://acme/prod//x",         // empty segment
            "spiffe://acme/../x",            // dot segment
            "spiffe://acme/x?y=1",           // query
            "spiffe://acme/x#frag",          // fragment
            "spiffe://user@acme/x",          // userinfo
            "spiffe://acme:8080/x",          // port
            "spiffe://ACME/x",               // uppercase trust domain
            "SPIFFE://acme/x",               // uppercase scheme
        ] {
            assert!(validate_spiffe(id).is_err(), "{id} should be rejected");
        }
    }
}

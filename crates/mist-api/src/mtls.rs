//! Mutual TLS for the ingest listener.
//!
//! When `CLIENT_CA_CERT` points at a PEM CA bundle, the API serves a
//! second, ingest-only HTTPS listener that requires a client certificate
//! chained to that CA. Verification happens inside the TLS handshake, so
//! unauthenticated peers never reach a handler. This proves membership in
//! the agent PKI — not which node (cert subjects are not mapped yet).

use std::sync::Arc;

use rustls::ServerConfig;

/// Build a `ServerConfig` that requires client certificates chained to
/// `ca_pem`, serving `cert_pem`/`key_pem`. ALPN mirrors axum-server's
/// `from_pem` (`h2`, `http/1.1`), which `RustlsConfig::from_config` does
/// not set on our behalf.
///
/// # Errors
///
/// Returns an error when any input holds no usable PEM block, the CA
/// bundle parses to zero anchors, or the key disagrees with the cert.
pub fn mtls_server_config(
    cert_pem: &[u8],
    key_pem: &[u8],
    ca_pem: &[u8],
) -> anyhow::Result<Arc<ServerConfig>> {
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut &cert_pem[..]).collect::<Result<_, _>>()?;
    if certs.is_empty() {
        anyhow::bail!("server cert PEM holds no certificates");
    }
    let key = rustls_pemfile::private_key(&mut &key_pem[..])?
        .ok_or_else(|| anyhow::anyhow!("server key PEM holds no private key"))?;
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut &ca_pem[..]) {
        roots.add(cert?)?;
    }
    if roots.is_empty() {
        anyhow::bail!("client CA PEM holds no certificates");
    }
    // Explicit ring provider throughout: the tree enables two providers,
    // so the ambient default may be unset (see main's pin).
    let provider: Arc<rustls::crypto::CryptoProvider> =
        Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()?;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| anyhow::anyhow!("TLS versions disagree with the ring provider"))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestPki {
        ca: Vec<u8>,
        server_cert: Vec<u8>,
        server_key: Vec<u8>,
    }

    /// CA plus a CA-issued server leaf. rcgen 0.14 signs leaves through
    /// an `Issuer`; `KeyPair` itself carries the public key.
    fn test_pki() -> TestPki {
        let mut ca_params = rcgen::CertificateParams::new(vec!["mist-test-ca".to_owned()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf_params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
        TestPki {
            ca: ca_cert.pem().into_bytes(),
            server_cert: leaf_cert.pem().into_bytes(),
            server_key: leaf_key.serialize_pem().into_bytes(),
        }
    }

    #[test]
    fn mtls_config_builds_from_ca_issued_pair() {
        let pki = test_pki();
        let config = mtls_server_config(&pki.server_cert, &pki.server_key, &pki.ca)
            .expect("valid inputs must build");
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn empty_ca_bundle_is_rejected() {
        let pki = test_pki();
        let err = mtls_server_config(&pki.server_cert, &pki.server_key, b"")
            .expect_err("empty CA must fail");
        assert!(err.to_string().contains("no certificates"), "{err}");
    }

    #[test]
    fn garbage_pem_is_rejected() {
        let pki = test_pki();
        assert!(mtls_server_config(b"not pem", &pki.server_key, &pki.ca).is_err());
        assert!(mtls_server_config(&pki.server_cert, b"not pem", &pki.ca).is_err());
        assert!(mtls_server_config(&pki.server_cert, &pki.server_key, b"not pem").is_err());
    }

    #[test]
    fn mismatched_key_is_rejected() {
        let pki = test_pki();
        let other_key = rcgen::KeyPair::generate().unwrap();
        assert!(
            mtls_server_config(
                &pki.server_cert,
                other_key.serialize_pem().as_bytes(),
                &pki.ca,
            )
            .is_err(),
            "wrong key must fail"
        );
    }
}

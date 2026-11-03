//! Agent TLS: server CA trust plus the mTLS client identity.

use crate::Args;

/// TLS materials from the `--tls-*` paths: the server CA bundle plus the
/// concatenated client cert+key identity.
#[cfg_attr(
    all(not(test), not(target_os = "linux")),
    allow(dead_code, reason = "only the Linux loader uses this")
)]
pub(crate) struct TlsMaterials {
    pub(crate) ca_pem: Option<Vec<u8>>,
    pub(crate) identity_pem: Option<Vec<u8>>,
}

/// Read TLS materials from the `--tls-*` paths. Cert and key must pair up;
/// anything else is a startup error (never a silent plaintext downgrade).
/// Paths — never key material — appear in errors.
#[cfg_attr(
    all(not(test), not(target_os = "linux")),
    allow(dead_code, reason = "only the Linux loader calls this")
)]
pub(crate) fn load_tls_materials(args: &Args) -> anyhow::Result<TlsMaterials> {
    let read = |path: &std::path::Path| {
        std::fs::read(path).map_err(|error| anyhow::anyhow!("reading {}: {error}", path.display()))
    };
    let ca_pem = args.tls_ca_cert.as_deref().map(read).transpose()?;
    let identity_pem = match (&args.tls_cert, &args.tls_key) {
        (None, None) => None,
        (Some(cert), Some(key)) => {
            let mut both = read(cert)?;
            both.extend_from_slice(&read(key)?);
            Some(both)
        }
        _ => anyhow::bail!("--tls-cert and --tls-key must both be set (or both unset)"),
    };
    Ok(TlsMaterials {
        ca_pem,
        identity_pem,
    })
}

/// Strict PEM decode: a garbled `--tls-*` path is a startup error, never
/// a client that silently trusts nothing or sends no identity (reqwest's
/// own parsers accept inputs we must reject, and take only the first cert
/// of a bundle).
#[cfg_attr(
    all(not(test), not(target_os = "linux")),
    allow(dead_code, reason = "only the Linux loader calls this")
)]
pub(crate) fn parse_certs(
    pem: &[u8],
    what: &str,
) -> anyhow::Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    use anyhow::Context as _;
    let certs = rustls_pemfile::certs(&mut &pem[..])
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parsing {what}"))?;
    if certs.is_empty() {
        anyhow::bail!("{what} holds no certificates");
    }
    Ok(certs)
}

/// Build the ingest HTTP client: 5s timeout, optional custom server CA,
/// optional client identity for mTLS.
#[cfg_attr(
    all(not(test), not(target_os = "linux")),
    allow(dead_code, reason = "only the Linux loader calls this")
)]
pub(crate) fn build_http_client(
    ca_pem: Option<&[u8]>,
    identity_pem: Option<&[u8]>,
) -> anyhow::Result<reqwest::Client> {
    use anyhow::Context as _;
    let mut builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(5));
    if let Some(pem) = ca_pem {
        for cert in &parse_certs(pem, "TLS CA PEM")? {
            let anchor =
                reqwest::Certificate::from_der(cert.as_ref()).context("loading TLS CA cert")?;
            builder = builder.add_root_certificate(anchor);
        }
    }
    if let Some(pem) = identity_pem {
        parse_certs(pem, "TLS identity PEM")?;
        let key = rustls_pemfile::private_key(&mut &pem[..]).context("parsing TLS identity PEM")?;
        if key.is_none() {
            anyhow::bail!("TLS identity PEM holds no private key");
        }
        let identity = reqwest::Identity::from_pem(pem).context("loading TLS identity")?;
        builder = builder.identity(identity);
    }
    Ok(builder.build()?)
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::{Args, build_http_client, load_tls_materials};

    struct ClientPki {
        ca: Vec<u8>,
        cert: Vec<u8>,
        key: Vec<u8>,
    }

    /// CA plus a CA-issued client leaf, mirroring the API's `TestPki`.
    fn client_pki() -> ClientPki {
        let mut ca_params = rcgen::CertificateParams::new(vec!["mist-test-ca".to_owned()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf_params = rcgen::CertificateParams::new(vec!["mist-agent".to_owned()]).unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
        ClientPki {
            ca: ca_cert.pem().into_bytes(),
            cert: leaf_cert.pem().into_bytes(),
            key: leaf_key.serialize_pem().into_bytes(),
        }
    }

    fn write_temp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("mist-agent-tls-test-{}-{name}", std::process::id()));
        std::fs::write(&path, bytes).expect("writing temp fixture");
        path
    }

    #[test]
    fn tls_options_default_to_off() {
        let args = Args::try_parse_from(["mist-agent"]).unwrap();
        let tls = load_tls_materials(&args).unwrap();
        assert!(tls.ca_pem.is_none());
        assert!(tls.identity_pem.is_none());
        build_http_client(None, None).expect("plain client must build");
    }

    #[test]
    fn tls_cert_and_key_must_pair() {
        let cert_only = Args::try_parse_from(["mist-agent", "--tls-cert", "a.pem"]).unwrap();
        assert!(load_tls_materials(&cert_only).is_err());
        let key_only = Args::try_parse_from(["mist-agent", "--tls-key", "a.pem"]).unwrap();
        assert!(load_tls_materials(&key_only).is_err());
    }

    #[test]
    fn tls_identity_loads_and_builds_client() {
        let pki = client_pki();
        let ca_path = write_temp("ca.pem", &pki.ca);
        let cert_path = write_temp("client.pem", &pki.cert);
        let key_path = write_temp("client-key.pem", &pki.key);
        let args = Args::try_parse_from([
            "mist-agent",
            "--tls-ca-cert",
            ca_path.to_str().unwrap(),
            "--tls-cert",
            cert_path.to_str().unwrap(),
            "--tls-key",
            key_path.to_str().unwrap(),
        ])
        .unwrap();
        let tls = load_tls_materials(&args).unwrap();
        assert!(tls.ca_pem.is_some());
        assert!(tls.identity_pem.is_some());
        build_http_client(tls.ca_pem.as_deref(), tls.identity_pem.as_deref())
            .expect("mTLS client must build");
        for path in [ca_path, cert_path, key_path] {
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn tls_client_rejects_garbage_pem() {
        assert!(build_http_client(Some(b"not pem"), None).is_err());
        assert!(build_http_client(None, Some(b"not pem")).is_err());
    }
}

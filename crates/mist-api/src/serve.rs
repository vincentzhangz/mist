//! Listener setup: plain/TLS main plus the ingest-only mTLS port.

use std::net::SocketAddr;

use anyhow::Context as _;

use crate::{
    mtls,
    routes::{app_router, ingest_router, router},
    state::AppState,
};

/// Run the listeners: plain or TLS main, plus the ingest-only mTLS port
/// when configured (in which case ingest leaves the main router, so the
/// main port can never bypass the handshake gate).
pub(crate) async fn serve(
    state: AppState,
    addr: SocketAddr,
    main_tls: Option<axum_server::tls_rustls::RustlsConfig>,
    mtls: Option<(SocketAddr, axum_server::tls_rustls::RustlsConfig)>,
) -> anyhow::Result<()> {
    if let Some((ingest_addr, ingest_tls)) = mtls {
        // mTLS mode: ingest leaves the main listener (no bypass) and gets
        // its own client-cert-gated port.
        tracing::info!(%addr, "mist-api listening with TLS");
        tracing::info!(%ingest_addr, "mist-api ingest listening with mTLS");
        let main_tls = main_tls.context("CLIENT_CA_CERT requires TLS_CERT and TLS_KEY")?;
        let main = axum_server::bind_rustls(addr, main_tls).serve(
            app_router(state.clone(), false).into_make_service_with_connect_info::<SocketAddr>(),
        );
        let ingest = axum_server::bind_rustls(ingest_addr, ingest_tls)
            .serve(ingest_router(state).into_make_service_with_connect_info::<SocketAddr>());
        let (main_out, ingest_out) = tokio::join!(main, ingest);
        main_out?;
        ingest_out?;
    } else if let Some(config) = main_tls {
        tracing::info!(%addr, "mist-api listening with TLS");
        axum_server::bind_rustls(addr, config)
            .serve(router(state).into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    } else {
        tracing::info!(%addr, "mist-api listening (plain HTTP)");
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(
            listener,
            router(state).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;
    }
    Ok(())
}

/// Listener plan from TLS env: main listener plain or TLS, plus an
/// optional ingest-only mTLS listener. Pure for testing; file reads and
/// config builds happen in [`tls_setup`].
struct TlsPlan {
    main_tls: bool,
    mtls_ingest_bind: Option<SocketAddr>,
}

fn plan_tls(
    cert: bool,
    key: bool,
    client_ca: bool,
    ingest_bind: Option<&str>,
) -> anyhow::Result<TlsPlan> {
    if cert != key {
        anyhow::bail!("TLS_CERT and TLS_KEY must both be set (or both unset)");
    }
    let mtls_ingest_bind = if client_ca {
        if !cert {
            anyhow::bail!(
                "CLIENT_CA_CERT requires TLS_CERT and TLS_KEY (client certs only exist inside TLS)"
            );
        }
        Some(
            ingest_bind
                .unwrap_or("0.0.0.0:3001")
                .parse()
                .context("parsing INGEST_BIND_ADDR")?,
        )
    } else {
        None
    };
    Ok(TlsPlan {
        main_tls: cert,
        mtls_ingest_bind,
    })
}

/// Listener TLS setup from env. Returns the main-listener config plus,
/// when `CLIENT_CA_CERT` is set, the (addr, config) for the ingest-only
/// mTLS listener. A half-mounted certificate is a startup error, so it
/// can never silently downgrade to plaintext (or to token-only ingest).
pub(crate) async fn tls_setup() -> anyhow::Result<(
    Option<axum_server::tls_rustls::RustlsConfig>,
    Option<(SocketAddr, axum_server::tls_rustls::RustlsConfig)>,
)> {
    let present = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());
    let cert = present("TLS_CERT");
    let key = present("TLS_KEY");
    let ca = present("CLIENT_CA_CERT");
    let plan = plan_tls(
        cert.is_some(),
        key.is_some(),
        ca.is_some(),
        present("INGEST_BIND_ADDR").as_deref(),
    )?;
    // plan_tls guarantees the pair is complete whenever TLS is on.
    let pair = cert.zip(key);
    let main = if plan.main_tls {
        let Some((cert, key)) = pair.as_ref() else {
            anyhow::bail!("TLS_CERT and TLS_KEY must both be set (or both unset)")
        };
        Some(
            axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
                .await
                .map_err(|error| {
                    anyhow::anyhow!("loading TLS cert/key ({cert}, {key}): {error}")
                })?,
        )
    } else {
        None
    };
    let mtls = match (plan.mtls_ingest_bind, ca) {
        (Some(addr), Some(ca)) => {
            let Some((cert, key)) = pair.as_ref() else {
                anyhow::bail!("CLIENT_CA_CERT requires TLS_CERT and TLS_KEY")
            };
            let read = |what: &str, path: &str| {
                std::fs::read(path)
                    .map_err(|error| anyhow::anyhow!("reading {what} {path}: {error}"))
            };
            let config = mtls::mtls_server_config(
                &read("TLS_CERT", cert)?,
                &read("TLS_KEY", key)?,
                &read("CLIENT_CA_CERT", &ca)?,
            )?;
            Some((
                addr,
                axum_server::tls_rustls::RustlsConfig::from_config(config),
            ))
        }
        _ => None,
    };
    Ok((main, mtls))
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;

    use super::*;
    use crate::test_helpers::*;

    #[tokio::test]
    async fn tls_serves_https_with_a_self_signed_cert() {
        // Same pin as main: the tree enables two rustls providers.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (state, _rx) = crate::test_helpers::test_state();
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let config = axum_server::tls_rustls::RustlsConfig::from_pem(
            certified.cert.pem().into_bytes(),
            certified.signing_key.serialize_pem().into_bytes(),
        )
        .await
        .unwrap();
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = std_listener.local_addr().unwrap();
        tokio::spawn(axum_server::from_tcp_rustls(std_listener, config).serve(
            crate::routes::router(state).into_make_service_with_connect_info::<SocketAddr>(),
        ));
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        let body = client
            .get(format!("https://127.0.0.1:{}/healthz", addr.port()))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(body, "ok");
    }
    #[test]
    fn plan_tls_matrix() {
        // Nothing set: plain main, no mTLS.
        let plan = plan_tls(false, false, false, None).unwrap();
        assert!(!plan.main_tls);
        assert!(plan.mtls_ingest_bind.is_none());
        // TLS pair: TLS main, no mTLS.
        let plan = plan_tls(true, true, false, None).unwrap();
        assert!(plan.main_tls);
        assert!(plan.mtls_ingest_bind.is_none());
        // CA: mTLS on the default ingest port.
        let plan = plan_tls(true, true, true, None).unwrap();
        assert!(plan.main_tls);
        assert_eq!(plan.mtls_ingest_bind.unwrap().port(), 3001);
        // Custom ingest bind honored.
        let plan = plan_tls(true, true, true, Some("127.0.0.1:3443")).unwrap();
        assert_eq!(plan.mtls_ingest_bind.unwrap().to_string(), "127.0.0.1:3443");
        // Half-mounted pair rejected.
        assert!(plan_tls(true, false, false, None).is_err());
        // CA without server TLS rejected.
        assert!(plan_tls(false, false, true, None).is_err());
        // Garbage bind rejected.
        assert!(plan_tls(true, true, true, Some("nope")).is_err());
    }
    /// rcgen CA plus server/client leaves, as PEM bytes.
    struct RoundtripPki {
        ca: Vec<u8>,
        server_cert: Vec<u8>,
        server_key: Vec<u8>,
        client_cert: Vec<u8>,
        client_key: Vec<u8>,
    }

    fn mtls_pki() -> RoundtripPki {
        let mut ca_params = rcgen::CertificateParams::new(vec!["mist-test-ca".to_owned()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        let leaf = |sans: Vec<String>| {
            let key = rcgen::KeyPair::generate().unwrap();
            let params = rcgen::CertificateParams::new(sans).unwrap();
            let cert = params.signed_by(&key, &issuer).unwrap();
            (cert.pem().into_bytes(), key.serialize_pem().into_bytes())
        };
        let (srv_cert, srv_key) = leaf(vec!["127.0.0.1".to_owned()]);
        let (cli_cert, cli_key) = leaf(vec!["mist-agent".to_owned()]);
        RoundtripPki {
            ca: ca_cert.pem().into_bytes(),
            server_cert: srv_cert,
            server_key: srv_key,
            client_cert: cli_cert,
            client_key: cli_key,
        }
    }
    #[tokio::test]
    async fn mtls_ingest_requires_client_cert() {
        // Same pin as main: the tree enables two rustls providers.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (state, mut rx) = crate::test_helpers::test_state();
        let pki = mtls_pki();
        let config = mtls::mtls_server_config(&pki.server_cert, &pki.server_key, &pki.ca).unwrap();
        let rustls_config = axum_server::tls_rustls::RustlsConfig::from_config(config);
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = std_listener.local_addr().unwrap();
        tokio::spawn(
            axum_server::from_tcp_rustls(std_listener, rustls_config).serve(
                crate::routes::ingest_router(state)
                    .into_make_service_with_connect_info::<SocketAddr>(),
            ),
        );
        let url = format!("https://127.0.0.1:{}/api/ingest", addr.port());
        let mut shipment = batch();
        shipment.flows.push(test_flow("node-1", None));
        let body = serde_json::to_string(&shipment).unwrap();
        let ca = reqwest::Certificate::from_pem(&pki.ca).unwrap();
        let identity = |cert: &[u8], key: &[u8]| {
            let mut both = cert.to_vec();
            both.extend_from_slice(key);
            reqwest::Identity::from_pem(&both).unwrap()
        };
        // Valid client cert: accepted, batch reaches the analyzer channel.
        let client = reqwest::Client::builder()
            .add_root_certificate(ca.clone())
            .identity(identity(&pki.client_cert, &pki.client_key))
            .build()
            .unwrap();
        let response = client
            .post(&url)
            .header("content-type", "application/json")
            .body(body.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(rx.recv().await.unwrap().node, "node-1");
        // No client cert: the handshake fails before any handler runs.
        let bare = reqwest::Client::builder()
            .add_root_certificate(ca)
            .build()
            .unwrap();
        assert!(
            bare.post(&url)
                .header("content-type", "application/json")
                .body(body.clone())
                .send()
                .await
                .is_err()
        );
        // Rogue-CA client cert: the handshake fails too.
        let rogue_pki = mtls_pki();
        let rogue = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(&pki.ca).unwrap())
            .identity(identity(&rogue_pki.client_cert, &rogue_pki.client_key))
            .build()
            .unwrap();
        assert!(
            rogue
                .post(&url)
                .header("content-type", "application/json")
                .body(body)
                .send()
                .await
                .is_err()
        );
    }
}

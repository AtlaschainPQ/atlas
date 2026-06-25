//! TLS-Konfiguration für P2P-Verbindungen
//!
//! Mainnet-Sicherheitsmodell:
//!   - Jeder Node hat eine stabile Identität (Node-ID = SHA256(cert)[..20])
//!   - Zertifikat + Schlüssel werden in data_dir persistiert (kein neues Cert pro Restart)
//!   - TOFU (Trust On First Use): für Outbound-Verbindungen wird der Cert-Fingerprint
//!     beim ersten Connect gespeichert und bei jedem weiteren Connect geprüft.
//!   - Signaturverifikation via ring-Provider (kein AcceptAnyCert mehr)

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use parking_lot::Mutex;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::info;

/// 20-Byte Node-ID (gekürzt-SHA256 des Zertifikats)
pub type NodeId = [u8; 20];

/// Berechnet eine 20-Byte Node-ID aus dem Zertifikat-DER.
pub fn node_id_from_cert(cert_der: &[u8]) -> NodeId {
    let hash = Sha256::digest(cert_der);
    hash[..20].try_into().expect("sha256 has 32 bytes")
}

/// Node-ID als Hex-String (40 Zeichen)
pub fn node_id_hex(id: &NodeId) -> String {
    hex::encode(id)
}

// ── TOFU-Store ────────────────────────────────────────────────────────────────

/// Speichert Cert-Fingerprints für bekannte Outbound-Peers (Trust On First Use).
///
/// Beim ersten Connect zu einer Adresse wird der Fingerprint gespeichert.
/// Danach wird bei jedem Connect geprüft ob der Fingerprint übereinstimmt.
/// Weicht er ab → Verbindung wird abgelehnt (möglicher MITM).
pub struct TofuStore {
    path: String,
    data: Mutex<HashMap<String, String>>, // "ip:port" → "sha256_hex"
}

impl std::fmt::Debug for TofuStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TofuStore").field("path", &self.path).finish_non_exhaustive()
    }
}

impl TofuStore {
    pub fn load(data_dir: &str) -> Self {
        let path = format!("{}/known_peers.json", data_dir);
        let data = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        TofuStore { path, data: Mutex::new(data) }
    }

    /// Prüft (und speichert bei Erstverbindung) den Cert-Fingerprint.
    pub fn check_or_trust(&self, addr: SocketAddr, cert_der: &[u8]) -> Result<(), String> {
        let fp  = hex::encode(Sha256::digest(cert_der));
        let key = addr.to_string();
        let mut data = self.data.lock();

        match data.get(&key) {
            Some(stored) if stored != &fp => {
                Err(format!(
                    "CERT_MISMATCH peer={} stored={}… got={}… — possible MITM! \
                     Delete {} to reset.",
                    addr, &stored[..16], &fp[..16], self.path
                ))
            }
            Some(_) => Ok(()), // bekannt, stimmt überein
            None => {
                // Erstverbindung: vertrauen und speichern
                info!("TOFU: trusted peer {} cert={}…", addr, &fp[..16]);
                data.insert(key, fp);
                let _ = std::fs::write(
                    &self.path,
                    serde_json::to_string_pretty(&*data).unwrap_or_default(),
                );
                Ok(())
            }
        }
    }
}

// ── TlsConfig ─────────────────────────────────────────────────────────────────

pub struct TlsConfig {
    pub acceptor: TlsAcceptor,
    pub node_id:  NodeId,
    tofu:         Arc<TofuStore>,
}

impl TlsConfig {
    /// Lädt (oder erzeugt) persistente Node-Identität und TLS-Konfiguration.
    ///
    /// Dateien in `data_dir`:
    ///   - `node_cert.der`  — selbstsigniertes TLS-Zertifikat
    ///   - `node_key.der`   — privater Schlüssel (PKCS8-DER)
    ///   - `known_peers.json` — TOFU-Fingerprint-Store
    pub fn load_or_generate(data_dir: &str) -> anyhow::Result<Self> {
        let cert_path = format!("{}/node_cert.der", data_dir);
        let key_path  = format!("{}/node_key.der", data_dir);

        std::fs::create_dir_all(data_dir)?;

        // Zertifikat und Schlüssel laden oder neu generieren
        let (cert_der_vec, key_der_vec) =
            if Path::new(&cert_path).exists() && Path::new(&key_path).exists() {
                let cert = std::fs::read(&cert_path)?;
                let key  = std::fs::read(&key_path)?;
                info!("Loaded existing node TLS certificate");
                (cert, key)
            } else {
                let generated = rcgen::generate_simple_self_signed(
                    vec!["atlas-node".to_string()],
                )?;
                let cert_bytes = generated.cert.der().to_vec();
                let key_bytes  = generated.key_pair.serialize_der();
                std::fs::write(&cert_path, &cert_bytes)?;
                std::fs::write(&key_path,  &key_bytes)?;
                info!("Generated new node TLS certificate (saved to {})", data_dir);
                (cert_bytes, key_bytes)
            };

        let node_id = node_id_from_cert(&cert_der_vec);
        info!("Node ID: {}", node_id_hex(&node_id));

        // Server-Konfiguration (eingehende Verbindungen)
        let cert_rustls = CertificateDer::from(cert_der_vec);
        let key_rustls  = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_der_vec),
        );
        let server_cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_rustls], key_rustls)?;

        let tofu = Arc::new(TofuStore::load(data_dir));

        Ok(TlsConfig {
            acceptor: TlsAcceptor::from(Arc::new(server_cfg)),
            node_id,
            tofu,
        })
    }

    /// Erstellt einen TLS-Connector mit TOFU-Verifikation für eine spezifische Adresse.
    /// Jede Outbound-Verbindung bekommt ihren eigenen Connector mit der Peer-Adresse.
    pub fn outbound_connector(&self, addr: SocketAddr) -> TlsConnector {
        let verifier = TofuVerifier {
            store: self.tofu.clone(),
            addr,
        };
        let client_cfg = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        TlsConnector::from(Arc::new(client_cfg))
    }
}

// ── TOFU-Verifier (TLS-Client-Seite) ─────────────────────────────────────────

#[derive(Debug)]
struct TofuVerifier {
    store: Arc<TofuStore>,
    addr:  SocketAddr,
}

impl ServerCertVerifier for TofuVerifier {
    fn verify_server_cert(
        &self,
        end_entity:    &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name:   &ServerName<'_>,
        _ocsp_response: &[u8],
        _now:           UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.store
            .check_or_trust(self.addr, end_entity.as_ref())
            .map(|_| ServerCertVerified::assertion())
            .map_err(|e| {
                tracing::warn!("{}", e);
                rustls::Error::General(e)
            })
    }

    /// Echte kryptografische Verifikation via ring-Provider.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert:    &CertificateDer<'_>,
        dss:     &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let algorithms = rustls::crypto::ring::default_provider()
            .signature_verification_algorithms;
        rustls::crypto::verify_tls12_signature(message, cert, dss, &algorithms)
    }

    /// Echte kryptografische Verifikation via ring-Provider.
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert:    &CertificateDer<'_>,
        dss:     &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let algorithms = rustls::crypto::ring::default_provider()
            .signature_verification_algorithms;
        rustls::crypto::verify_tls13_signature(message, cert, dss, &algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs::File;
use std::io::BufReader as StdBufReader; // Avoid conflict with tokio::io::BufReader
use std::path::Path;
use std::sync::Arc;

// --- TLS Specific Imports ---
// Use rustls types directly for config
// Use the PrivateKeyDer enum which covers different key types
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, ServerConfig};

// --- Shared Data Structures ---
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MyRequest {
    pub action: String,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct MyResponse {
    pub result: String,
}
#[derive(Serialize, Debug)]
pub struct BenchmarkStats {
    pub total: u32,
    pub success: u32,
    pub fail: u32,
    pub avg_latency_ms: f64,
    pub min_ms: f64,
    pub max_ms: f64,
    pub qps: f64,
}

// --- TLS Configuration ---

// Load server cert and key, returning the correct PrivateKeyDer enum
pub fn load_certs_and_key(
    cert_path: &str,
    key_path: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), Box<dyn Error + Send + Sync>> { // Return PrivateKeyDer enum
    // Load certificate chain (try PEM first)
    let certs = {
        let cert_file = File::open(Path::new(cert_path)).map_err(|e| format!("Failed to open cert file {}: {}", cert_path, e))?;
        let mut cert_reader = StdBufReader::new(cert_file);
        rustls_pemfile::certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Failed to parse PEM cert file {}: {}", cert_path, e))?
    };

    let certs = if certs.is_empty() {
        // If no PEM certs found, assume DER format
        println!("No PEM certs found, loading cert as DER...");
        let cert_bytes = std::fs::read(cert_path)
            .map_err(|e| format!("Failed to read DER cert file {}: {}", cert_path, e))?;
        vec![CertificateDer::from(cert_bytes)]
    } else {
        println!("Loaded certs as PEM.");
        certs
    };


    // Load private key (try PEM PKCS8 first)
    let key_file = File::open(Path::new(key_path)).map_err(|e| format!("Failed to open key file {}: {}", key_path, e))?;
    let mut key_reader = StdBufReader::new(key_file);

    let key = if let Some(key_res) = rustls_pemfile::pkcs8_private_keys(&mut key_reader).next() {
        let key_der = key_res.map_err(|e| format!("Failed to parse PEM PKCS8 key from {}: {}", key_path, e))?;
        println!("Loaded key as PEM PKCS8.");
        PrivateKeyDer::Pkcs8(key_der.into()) // Wrap in enum
    } else {
        // Reset reader and try PEM RSA (PKCS1)
        // Fix lifetime issue by reading the file content first
        let key_bytes_for_rsa = std::fs::read(key_path)
             .map_err(|e| format!("Failed to read key file {} for RSA check: {}", key_path, e))?;
        let mut key_reader_rsa = std::io::Cursor::new(key_bytes_for_rsa); // Use Cursor for in-memory reader

        let key_result = if let Some(key_res) = rustls_pemfile::rsa_private_keys(&mut key_reader_rsa).next() {
             let key_der = key_res.map_err(|e| format!("Failed to parse PEM RSA key from {}: {}", key_path, e))?;
             println!("Loaded key as PEM RSA (PKCS1).");
             PrivateKeyDer::Pkcs1(key_der.into()) // Wrap in enum
        } else {
            // If no PEM keys found, assume DER PKCS8 (most common DER format)
            println!("No PEM keys found, loading key as DER PKCS8...");
            let key_bytes = std::fs::read(key_path)
                .map_err(|e| format!("Failed to read DER key file {}: {}", key_path, e))?;
            // If no PEM keys found, assume DER PKCS8 (most common DER format)
            println!("No PEM keys found, loading key as DER PKCS8...");
            // Read the file again for DER loading if RSA PEM failed
            let key_bytes_der = std::fs::read(key_path)
                .map_err(|e| format!("Failed to read DER key file {}: {}", key_path, e))?;
            // Note: This assumes the DER key is PKCS8. If it could be PKCS1 DER, more logic needed.
            PrivateKeyDer::Pkcs8(key_bytes_der.into()) // Wrap in enum
        };
        key_result // Assign the result of the if/else block
    };


    Ok((certs, key))
}


// Create a TLS ServerConfig
pub fn create_server_config(cert_path: &str, key_path: &str) -> Result<Arc<ServerConfig>, Box<dyn Error + Send + Sync>> {
    let (certs, key) = load_certs_and_key(cert_path, key_path)?;
    // Use the loaded key directly (it's now the correct PrivateKeyDer enum)
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key) // This now accepts the PrivateKeyDer enum
        .map_err(|e| format!("Failed to create TLS server config: {}", e))?;
    Ok(Arc::new(config))
}


// --- !!! WARNING: INSECURE CLIENT CONFIGURATION FOR TESTING ONLY !!! ---
pub mod danger {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified};
    // Import the generic CryptoProvider trait
    use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
    use rustls::pki_types;
    use rustls::pki_types::ServerName;
    // Removed unused CertificateError
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};
    use std::sync::Arc;

    #[derive(Debug)]
    pub struct NoServerVerification {
        // Store the default provider when creating the verifier
        provider: Arc<CryptoProvider>,
    }

    impl NoServerVerification {
        pub fn new(provider: Arc<CryptoProvider>) -> Self {
            Self { provider }
        }
    }

    impl rustls::client::danger::ServerCertVerifier for NoServerVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &pki_types::CertificateDer<'_>,
            _intermediates: &[pki_types::CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: pki_types::UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        // Use the stored provider's algorithms
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &pki_types::CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            verify_tls12_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms, // Use provider field
            )
        }

        // Use the stored provider's algorithms
        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &pki_types::CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            verify_tls13_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms, // Use provider field
            )
        }

        // Use the stored provider's algorithms
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.provider.signature_verification_algorithms.supported_schemes() // Use provider field
        }
    }
}
// --- !!! END OF INSECURE CLIENT CONFIGURATION !!! ---

use rustls::RootCertStore; // Import RootCertStore

// Create a TLS ClientConfig
// If ca_cert_path is Some, it verifies the server using the provided CA cert.
// If ca_cert_path is None, it uses an INSECURE configuration that trusts any server cert.
pub fn create_client_config(ca_cert_path: Option<&str>) -> Result<Arc<ClientConfig>, Box<dyn Error + Send + Sync>> {
    let config_builder = ClientConfig::builder();

    let config = match ca_cert_path {
        Some(path) => {
            println!("Loading CA certificate from: {}", path);
            let mut root_store = RootCertStore::empty();
            let ca_file = File::open(Path::new(path))
                .map_err(|e| format!("Failed to open CA cert file {}: {}", path, e))?;
            let mut reader = StdBufReader::new(ca_file);

            // Add CA certs from the PEM file
            let certs_added = rustls_pemfile::certs(&mut reader)
                 .collect::<Result<Vec<_>, _>>()
                 .map_err(|e| format!("Failed to parse CA cert file {}: {}", path, e))?;

            if certs_added.is_empty() {
                 return Err(format!("No valid PEM certificates found in CA file: {}", path).into());
            }

            root_store.add_parsable_certificates(certs_added);


            // Build config with root store for verification
            config_builder
                .with_root_certificates(root_store)
                .with_no_client_auth()
        }
        None => {
            eprintln!("WARN: No CA certificate provided. Using INSECURE client configuration that trusts any server certificate.");
            // Get the currently installed default crypto provider for the insecure verifier
            let provider = rustls::crypto::CryptoProvider::get_default()
                .ok_or("No default crypto provider found or configured for insecure mode")?;
            // Build insecure config
            config_builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(danger::NoServerVerification::new(provider.clone())))
                .with_no_client_auth()
        }
    };

    Ok(Arc::new(config))
}

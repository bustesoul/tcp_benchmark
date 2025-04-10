// Import necessary crates and modules
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs::File;
use std::io::BufReader as StdBufReader; // Avoid conflict with tokio::io::BufReader
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

// --- TLS Specific Imports ---
use tokio_rustls::TlsAcceptor;
use tokio_rustls::TlsConnector;
// Use rustls types directly for config
// Use the PrivateKeyDer enum which covers different key types
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, ServerConfig};

// --- Shared Data Structures --- (Keep as before)
#[derive(Serialize, Deserialize, Debug, Clone)]
struct MyRequest {
    action: String,
}
#[derive(Serialize, Deserialize, Debug)]
struct MyResponse {
    result: String,
}
#[derive(Serialize, Debug)]
struct BenchmarkStats {
    total: u32,
    success: u32,
    fail: u32,
    avg_latency_ms: f64,
    min_ms: f64,
    max_ms: f64,
    qps: f64,
}

// --- Configuration Constants ---
const TCP_SERVER_ADDR: &str = "127.0.0.1:8081";
const CONCURRENT_TASKS: usize = 10;
const REQUESTS_PER_TASK: u32 = 1000;
const CERT_PATH: &str = "/Users/buste/RustroverProjects/quic_demo/certs/cert.der";
const KEY_PATH: &str = "/Users/buste/RustroverProjects/quic_demo/certs/key.der";
const TLS_SERVER_NAME: &str = "localhost";

// --- TLS Configuration ---

// Load server cert and key, returning the correct PrivateKeyDer enum
fn load_certs_and_key(
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
        let mut key_reader = StdBufReader::new(File::open(Path::new(key_path))
            .map_err(|e| format!("Failed to open key file {} again: {}", key_path, e))?);
        if let Some(key_res) = rustls_pemfile::rsa_private_keys(&mut key_reader).next() {
            let key_der = key_res.map_err(|e| format!("Failed to parse PEM RSA key from {}: {}", key_path, e))?;
            println!("Loaded key as PEM RSA (PKCS1).");
            PrivateKeyDer::Pkcs1(key_der.into()) // Wrap in enum
        } else {
            // If no PEM keys found, assume DER PKCS8 (most common DER format)
            println!("No PEM keys found, loading key as DER PKCS8...");
            let key_bytes = std::fs::read(key_path)
                .map_err(|e| format!("Failed to read DER key file {}: {}", key_path, e))?;
            // Note: This assumes the DER key is PKCS8. If it could be PKCS1 DER, more logic needed.
            PrivateKeyDer::Pkcs8(key_bytes.into()) // Wrap in enum
        }
    };


    Ok((certs, key))
}


// Create a TLS ServerConfig
fn create_server_config() -> Result<Arc<ServerConfig>, Box<dyn Error + Send + Sync>> {
    let (certs, key) = load_certs_and_key(CERT_PATH, KEY_PATH)?;
    // Use the loaded key directly (it's now the correct PrivateKeyDer enum)
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key) // This now accepts the PrivateKeyDer enum
        .map_err(|e| format!("Failed to create TLS server config: {}", e))?;
    Ok(Arc::new(config))
}


// --- !!! WARNING: INSECURE CLIENT CONFIGURATION FOR TESTING ONLY !!! ---
mod danger {
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

// Create a TLS ClientConfig (INSECURE: trusts any server cert)
fn create_client_config() -> Result<Arc<ClientConfig>, Box<dyn Error + Send + Sync>> {
    // Get the currently installed default crypto provider
    let provider = rustls::crypto::CryptoProvider::get_default()
        .ok_or("No default crypto provider found or configured")?;
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(danger::NoServerVerification::new(provider.clone())))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

// --- TCP+TLS Server Implementation --- (Keep as before)
async fn handle_tls_connection(
    tls_stream: tokio_rustls::server::TlsStream<TcpStream>,
    addr: SocketAddr,
) {
    println!("TLS: New connection from {}", addr);
    let (reader, writer) = tokio::io::split(tls_stream);
    let mut buf_reader = BufReader::new(reader);
    let mut mut_writer = writer;
    let mut line = String::new();

    loop {
        line.clear();
        match buf_reader.read_line(&mut line).await {
            Ok(0) => {
                // Comment out for benchmark speed
                // println!("TLS: Connection closed by {}", addr);
                break;
            }
            Ok(_) => {
                let request: MyRequest = match serde_json::from_str(&line) {
                    Ok(req) => req,
                    Err(e) => {
                        eprintln!("TLS: Failed to parse request from {}: {}", addr, e);
                        let error_response = MyResponse { result: format!("Error: Invalid request format - {}", e) };
                        let response_str = serde_json::to_string(&error_response).unwrap_or_default() + "\n";
                        let _ = mut_writer.write_all(response_str.as_bytes()).await;
                        break;
                    }
                };
                let response = MyResponse { result: format!("TLS Server got action: {}", request.action) };
                match serde_json::to_string(&response) {
                    Ok(response_str) => {
                        let response_bytes = (response_str + "\n").into_bytes();
                        if let Err(e) = mut_writer.write_all(&response_bytes).await {
                            eprintln!("TLS: Failed to write response to {}: {}", addr, e);
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("TLS: Failed to serialize response: {}", e);
                        let response_bytes = (r#"{"result":"Error: Failed to serialize response"}\n"#).as_bytes();
                        if let Err(e_write) = mut_writer.write_all(response_bytes).await {
                            eprintln!("TLS: Failed to write error response to {}: {}", addr, e_write);
                        }
                        break;
                    }
                }
            }
            Err(e) => {
                if e.kind() != std::io::ErrorKind::ConnectionAborted && e.kind() != std::io::ErrorKind::ConnectionReset {
                    eprintln!("TLS: Error reading from {}: {}", addr, e);
                } // Less verbose logging for common close errors
                break;
            }
        }
    }
    // Comment out for benchmark speed
    // println!("TLS: Finished handling connection from {}", addr);
}

async fn run_tls_server() -> Result<(), Box<dyn Error + Send + Sync>> {
    let server_config = create_server_config()?;
    let acceptor = TlsAcceptor::from(server_config);
    let listener = TcpListener::bind(TCP_SERVER_ADDR).await?;
    println!("TLS Server listening on {}", TCP_SERVER_ADDR);
    loop {
        let (socket, addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            match acceptor.accept(socket).await {
                Ok(tls_stream) => { handle_tls_connection(tls_stream, addr).await; }
                Err(e) => { eprintln!("TLS handshake error from {}: {}", addr, e); }
            }
        });
    }
}


// --- TCP+TLS Client Benchmark Implementation --- (Keep as before)
async fn run_single_tls_task(
    server_addr: SocketAddr,
    tls_connector: Arc<TlsConnector>,
    tls_server_name: Arc<rustls::pki_types::ServerName<'static>>,
    request_template: Arc<MyRequest>,
    num_requests: u32,
) -> Result<(u32, u32, Vec<f64>), Box<dyn Error + Send + Sync>> {
    let stream = TcpStream::connect(server_addr).await?;
    let tls_stream = tls_connector
        .connect(tls_server_name.as_ref().to_owned(), stream)
        .await?;
    let (reader, writer) = tokio::io::split(tls_stream);
    let mut buf_reader = BufReader::new(reader);
    let mut mut_writer = writer;
    let mut response_line = String::new();
    let mut success_count = 0;
    let mut fail_count = 0;
    let mut durations_ms = Vec::with_capacity(num_requests as usize);

    for i in 0..num_requests {
        let request = MyRequest { action: format!("{}-{}", request_template.action, i) };
        let start_time = Instant::now();
        let request_str = match serde_json::to_string(&request) {
            Ok(s) => s + "\n",
            Err(e) => { eprintln!("TLS Client: Failed to serialize request {}: {}", i, e); fail_count += 1; continue; }
        };
        if let Err(e) = mut_writer.write_all(request_str.as_bytes()).await {
            eprintln!("TLS Client: Failed to write request {}: {}", i, e); fail_count += 1; return Ok((success_count, fail_count + (num_requests - i), durations_ms));
        }
        response_line.clear();
        match buf_reader.read_line(&mut response_line).await {
            Ok(0) => { eprintln!("TLS Client: Server closed connection during request {}", i); fail_count += 1; return Ok((success_count, fail_count + (num_requests - i), durations_ms)); }
            Ok(_) => {
                if let Ok(_response) = serde_json::from_str::<MyResponse>(&response_line) {
                    let duration = start_time.elapsed(); durations_ms.push(duration.as_secs_f64() * 1000.0); success_count += 1;
                } else { eprintln!("TLS Client: Failed to parse response for request {}: '{}'", i, response_line.trim()); fail_count += 1; }
            }
            Err(e) => { eprintln!("TLS Client: Failed to read response for request {}: {}", i, e); fail_count += 1; return Ok((success_count, fail_count + (num_requests - i), durations_ms)); }
        }
    }
    Ok((success_count, fail_count, durations_ms))
}

async fn run_concurrent_benchmark_tls(
    request: MyRequest,
    concurrent_tasks: usize,
    requests_per_task: u32,
) -> Result<BenchmarkStats, Box<dyn Error + Send + Sync>> {
    let server_addr: SocketAddr = TCP_SERVER_ADDR.parse()?;
    let client_config = create_client_config()?;
    let tls_connector = Arc::new(TlsConnector::from(client_config));
    let server_name = rustls::pki_types::ServerName::try_from(TLS_SERVER_NAME)
        .map_err(|e| format!("Invalid TLS server name '{}': {}", TLS_SERVER_NAME, e))?
        .to_owned();
    let shared_server_name = Arc::new(server_name);
    let shared_request = Arc::new(request);
    let mut tasks = Vec::new();
    let total_requests_expected = concurrent_tasks * requests_per_task as usize;

    println!(
        "Starting TCP+TLS Benchmark: {} concurrent tasks, {} requests per task...",
        concurrent_tasks, requests_per_task
    );

    for _ in 0..concurrent_tasks {
        let req_clone = shared_request.clone();
        let connector_clone = tls_connector.clone();
        let server_name_clone = shared_server_name.clone();
        tasks.push(tokio::spawn(run_single_tls_task(
            server_addr, connector_clone, server_name_clone, req_clone, requests_per_task,
        )));
    }

    let all_results = futures::future::join_all(tasks).await;
    let mut total_success = 0;
    let mut total_fail = 0;
    let mut all_latencies_ms: Vec<f64> = Vec::with_capacity(total_requests_expected);

    for result in all_results {
        match result {
            Ok(Ok((task_success, task_fail, task_durations))) => { total_success += task_success; total_fail += task_fail; all_latencies_ms.extend(task_durations); }
            Ok(Err(e)) => { eprintln!("TLS benchmark task failed during setup/connection: {}", e); total_fail += requests_per_task; }
            Err(e) => { eprintln!("TLS benchmark task panicked: {}", e); total_fail += requests_per_task; }
        }
    }
    let total_attempted = total_requests_expected as u32;
    total_fail = total_fail.min(total_attempted.saturating_sub(total_success));
    let (min, max, avg) = if all_latencies_ms.is_empty() { (0.0, 0.0, 0.0) } else {
        let min = all_latencies_ms.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = all_latencies_ms.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let sum: f64 = all_latencies_ms.iter().sum();
        let avg = sum / all_latencies_ms.len() as f64;
        (min, max, avg)
    };
    Ok(BenchmarkStats { total: total_attempted, success: total_success, fail: total_fail, avg_latency_ms: avg, min_ms: min, max_ms: max, qps: 0.0 })
}

// --- Main Function --- (Keep as before, runs TLS versions now)
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    println!("Starting TCP+TLS Server in background...");
    tokio::spawn(async {
        if let Err(e) = run_tls_server().await { eprintln!("TLS Server error: {}", e); }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    println!("Server likely started.");

    let request = MyRequest { action: "ping_tls".to_string() };
    println!("Running TCP+TLS Client Benchmark...");
    let start_benchmark = Instant::now();
    let stats = run_concurrent_benchmark_tls( request, CONCURRENT_TASKS, REQUESTS_PER_TASK, ).await?;
    let benchmark_duration = start_benchmark.elapsed();
    let final_qps = if benchmark_duration.as_secs_f64() > 0.0 { stats.success as f64 / benchmark_duration.as_secs_f64() } else { 0.0 };
    let final_stats = BenchmarkStats { qps: final_qps, ..stats };

    let json_report = serde_json::to_string_pretty(&final_stats)?;
    println!("\n--- TCP+TLS Benchmark Report ---");
    println!("{}", json_report);
    println!("Benchmark finished. Server is still running in the background.");
    Ok(())
}
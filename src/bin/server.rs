use clap::Parser;
use std::error::Error;
use std::net::SocketAddr;
use tcp_benchmark_lib::{create_server_config, MyRequest, MyResponse}; // Import from lib
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

/// Simple TLS Echo Server
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Server address to bind to (e.g., 127.0.0.1:8081)
    #[arg(short, long, default_value = "127.0.0.1:8081")]
    addr: String,

    /// Path to the certificate file (DER or PEM)
    #[arg(
        short,
        long,
        default_value = "/Users/buste/RustroverProjects/quic_demo/certs/cert.der"
    )]
    cert: String,

    /// Path to the private key file (DER or PEM)
    #[arg(
        short,
        long,
        default_value = "/Users/buste/RustroverProjects/quic_demo/certs/key.der"
    )]
    key: String,
}

// --- TCP+TLS Server Implementation ---
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
                // Connection closed
                break;
            }
            Ok(_) => {
                let request: MyRequest = match serde_json::from_str(&line) {
                    Ok(req) => req,
                    Err(e) => {
                        eprintln!("TLS: Failed to parse request from {}: {}", addr, e);
                        let error_response = MyResponse {
                            result: format!("Error: Invalid request format - {}", e),
                        };
                        let response_str =
                            serde_json::to_string(&error_response).unwrap_or_default() + "\n";
                        let _ = mut_writer.write_all(response_str.as_bytes()).await;
                        break; // Close connection on bad request
                    }
                };
                let response = MyResponse {
                    result: format!("TLS Server got action: {}", request.action),
                };
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
                        // Send generic error if serialization fails
                        let response_bytes =
                            (r#"{"result":"Error: Failed to serialize response"}\n"#).as_bytes();
                        if let Err(e_write) = mut_writer.write_all(response_bytes).await {
                            eprintln!(
                                "TLS: Failed to write error response to {}: {}",
                                addr, e_write
                            );
                        }
                        break; // Close connection on serialization error
                    }
                }
            }
            Err(e) => {
                if e.kind() != std::io::ErrorKind::ConnectionAborted
                    && e.kind() != std::io::ErrorKind::ConnectionReset
                {
                    eprintln!("TLS: Error reading from {}: {}", addr, e);
                }
                break;
            }
        }
    }
    println!("TLS: Finished handling connection from {}", addr);
}

async fn run_tls_server(
    addr: &str,
    cert_path: &str,
    key_path: &str,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let server_config = create_server_config(cert_path, key_path)?;
    let acceptor = TlsAcceptor::from(server_config);
    let listener = TcpListener::bind(addr).await?;
    println!("TLS Server listening on {}", addr);
    loop {
        let (socket, peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            match acceptor.accept(socket).await {
                Ok(tls_stream) => {
                    handle_tls_connection(tls_stream, peer_addr).await;
                }
                Err(e) => {
                    eprintln!("TLS handshake error from {}: {}", peer_addr, e);
                }
            }
        });
    }
}

// --- Main Function ---
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args = Args::parse();
    println!("Starting TCP+TLS Server...");
    if let Err(e) = run_tls_server(&args.addr, &args.cert, &args.key).await {
        eprintln!("Server error: {}", e);
        std::process::exit(1);
    }
    Ok(())
}

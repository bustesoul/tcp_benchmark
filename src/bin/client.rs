use clap::Parser;
use futures::future::join_all;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tcp_benchmark_lib::{create_client_config, BenchmarkStats, MyRequest, MyResponse}; // Import from lib
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Simple TLS Benchmark Client
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Server address to connect to (e.g., 127.0.0.1:8081)
    #[arg(short, long, default_value = "127.0.0.1:8081")]
    addr: String,

    /// Number of concurrent client tasks
    #[arg(short, long, default_value_t = 10)]
    concurrency: usize,

    /// Number of requests per task
    #[arg(short, long, default_value_t = 1000)]
    requests: u32,

    /// TLS server name for SNI (use 'localhost' for self-signed certs)
    #[arg(long, default_value = "localhost")]
    server_name: String,

    /// Optional path to the CA certificate file (PEM format) for server verification.
    /// If not provided, server certificate will not be verified (INSECURE).
    #[arg(long)]
    ca_cert: Option<String>,
}

// --- TCP+TLS Client Benchmark Implementation ---
async fn run_single_tls_task(
    server_addr: SocketAddr,
    tls_connector: Arc<TlsConnector>,
    tls_server_name: Arc<rustls::pki_types::ServerName<'static>>,
    request_template: Arc<MyRequest>,
    num_requests: u32,
) -> Result<(u32, u32, Vec<f64>), Box<dyn Error + Send + Sync>> {
    let stream = TcpStream::connect(server_addr).await?;
    // Clone the server name Arc before moving it into the connect call
    let server_name_ref = tls_server_name.as_ref().to_owned();
    let tls_stream = tls_connector.connect(server_name_ref, stream).await?;
    let (reader, writer) = tokio::io::split(tls_stream);
    let mut buf_reader = BufReader::new(reader);
    let mut mut_writer = writer;
    let mut response_line = String::new();
    let mut success_count = 0;
    let mut fail_count = 0;
    let mut durations_ms = Vec::with_capacity(num_requests as usize);

    for i in 0..num_requests {
        let request = MyRequest {
            action: format!("{}-{}", request_template.action, i),
            payload: "pingpingpingpingpingpingpingpingpingpingpingpingpingpingping".to_string(),
        };
        let start_time = Instant::now();
        let request_str = match serde_json::to_string(&request) {
            Ok(s) => s + "\n",
            Err(e) => {
                eprintln!("TLS Client: Failed to serialize request {}: {}", i, e);
                fail_count += 1;
                continue;
            }
        };
        if let Err(e) = mut_writer.write_all(request_str.as_bytes()).await {
            eprintln!("TLS Client: Failed to write request {}: {}", i, e);
            fail_count += 1;
            // If write fails, assume remaining requests also fail
            return Ok((
                success_count,
                fail_count + (num_requests - 1 - i),
                durations_ms,
            ));
        }
        response_line.clear();
        match buf_reader.read_line(&mut response_line).await {
            Ok(0) => {
                eprintln!("TLS Client: Server closed connection during request {}", i);
                fail_count += 1;
                // If server closes connection, assume remaining requests also fail
                return Ok((
                    success_count,
                    fail_count + (num_requests - 1 - i),
                    durations_ms,
                ));
            }
            Ok(_) => {
                if let Ok(_response) = serde_json::from_str::<MyResponse>(&response_line) {
                    let duration = start_time.elapsed();
                    durations_ms.push(duration.as_secs_f64() * 1000.0);
                    success_count += 1;
                } else {
                    eprintln!(
                        "TLS Client: Failed to parse response for request {}: '{}'",
                        i,
                        response_line.trim()
                    );
                    fail_count += 1;
                }
            }
            Err(e) => {
                eprintln!(
                    "TLS Client: Failed to read response for request {}: {}",
                    i, e
                );
                fail_count += 1;
                // If read fails, assume remaining requests also fail
                return Ok((
                    success_count,
                    fail_count + (num_requests - 1 - i),
                    durations_ms,
                ));
            }
        }
    }
    Ok((success_count, fail_count, durations_ms))
}

async fn run_concurrent_benchmark_tls(
    server_addr_str: &str,
    tls_server_name_str: &str,
    ca_cert_path: Option<&str>, // Add CA cert path parameter
    request: MyRequest,
    concurrent_tasks: usize,
    requests_per_task: u32,
) -> Result<BenchmarkStats, Box<dyn Error + Send + Sync>> {
    let server_addr: SocketAddr = server_addr_str.parse()?;
    // Pass the CA cert path to create_client_config
    let client_config = create_client_config(ca_cert_path)?;
    let tls_connector = Arc::new(TlsConnector::from(client_config));
    let server_name = rustls::pki_types::ServerName::try_from(tls_server_name_str)
        .map_err(|e| format!("Invalid TLS server name '{}': {}", tls_server_name_str, e))?
        .to_owned();
    let shared_server_name = Arc::new(server_name);
    let shared_request = Arc::new(request);
    let mut tasks = Vec::new();
    let total_requests_expected = concurrent_tasks * requests_per_task as usize;

    println!(
        "Starting TCP+TLS Benchmark: {} concurrent tasks, {} requests per task...",
        concurrent_tasks, requests_per_task
    );
    println!(
        "Targeting server: {}, TLS Name: {}",
        server_addr_str, tls_server_name_str
    );

    for _ in 0..concurrent_tasks {
        let req_clone = shared_request.clone();
        let connector_clone = tls_connector.clone();
        let server_name_clone = shared_server_name.clone();
        tasks.push(tokio::spawn(run_single_tls_task(
            server_addr,
            connector_clone,
            server_name_clone,
            req_clone,
            requests_per_task,
        )));
    }

    let all_results = join_all(tasks).await;
    let mut total_success = 0;
    let mut total_fail = 0;
    let mut all_latencies_ms: Vec<f64> = Vec::with_capacity(total_requests_expected);

    for result in all_results {
        match result {
            Ok(Ok((task_success, task_fail, task_durations))) => {
                total_success += task_success;
                total_fail += task_fail;
                all_latencies_ms.extend(task_durations);
            }
            Ok(Err(e)) => {
                eprintln!("TLS benchmark task failed during setup/connection: {}", e);
                // Assume all requests for this failed task are lost
                total_fail += requests_per_task;
            }
            Err(e) => {
                eprintln!("TLS benchmark task panicked: {}", e);
                // Assume all requests for this failed task are lost
                total_fail += requests_per_task;
            }
        }
    }

    // Ensure total_fail doesn't exceed the number of requests not successfully completed.
    let total_attempted = total_requests_expected as u32;
    total_fail = total_fail.min(total_attempted.saturating_sub(total_success));

    let (min, max, avg) = if all_latencies_ms.is_empty() {
        (0.0, 0.0, 0.0)
    } else {
        let min = all_latencies_ms
            .iter()
            .cloned()
            .fold(f64::INFINITY, f64::min);
        let max = all_latencies_ms
            .iter()
            .cloned()
            .fold(f64::NEG_INFINITY, f64::max);
        let sum: f64 = all_latencies_ms.iter().sum();
        let avg = sum / all_latencies_ms.len() as f64;
        (min, max, avg)
    };

    Ok(BenchmarkStats {
        total: total_attempted,
        success: total_success,
        fail: total_fail,
        avg_latency_ms: avg,
        min_ms: min,
        max_ms: max,
        qps: 0.0, // QPS will be calculated in main based on total time
    })
}

// --- Main Function ---
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args = Args::parse();

    // Give server a moment to start if run concurrently (optional)
    // tokio::time::sleep(Duration::from_millis(200)).await;

    let request = MyRequest {
        action: "ping_tls".to_string(),
        payload: "pingpingpingpingpingpingpingpingpingpingpingpingpingpingping".to_string(),
    };
    println!("Running TCP+TLS Client Benchmark...");
    let start_benchmark = Instant::now();

    let stats = run_concurrent_benchmark_tls(
        &args.addr,
        &args.server_name,
        args.ca_cert.as_deref(), // Pass the optional CA cert path
        request,
        args.concurrency,
        args.requests,
    )
    .await?;

    let benchmark_duration = start_benchmark.elapsed();
    let final_qps = if benchmark_duration.as_secs_f64() > 0.0 {
        stats.success as f64 / benchmark_duration.as_secs_f64()
    } else {
        0.0
    };

    let final_stats = BenchmarkStats {
        qps: final_qps,
        ..stats
    };

    let json_report = serde_json::to_string_pretty(&final_stats)?;
    println!("\n--- TCP+TLS Benchmark Report ---");
    println!("{}", json_report);
    println!("Total benchmark duration: {:?}", benchmark_duration);

    Ok(())
}

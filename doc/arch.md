# 项目架构与功能文档

## 概述

本项目是一个基于 TCP+TLS 的客户端/服务器性能基准测试工具。它包含一个服务器端应用程序、一个客户端应用程序以及一个共享库，用于处理通用逻辑，如数据结构和 TLS 配置。

## 项目结构

- `Cargo.toml` / `Cargo.lock`: 定义项目依赖和管理构建配置。
- `src/`: 包含源代码。
  - `bin/`: 包含二进制可执行文件。
    - `client.rs`: 客户端应用程序的入口点。
    - `server.rs`: 服务器端应用程序的入口点。
  - `lib.rs`: 包含客户端和服务器共享的代码库。
- `certs/`: (推测) 存放 TLS 证书和密钥文件。
- `doc/`: (新建) 存放项目文档。
  - `arch.md`: 本文档。

## 主要组件

### 1. 服务器 (`src/bin/server.rs`)

- **功能**: 监听指定的 TCP 地址和端口，接受 TLS 加密的连接，并处理来自客户端的请求。
- **启动**: 通过命令行参数指定监听地址 (`--addr`)、证书文件路径 (`--cert`) 和私钥文件路径 (`--key`)。
  ```rust
  // Example structure from server.rs
  struct Args {
      /// Server address to bind to (e.g., 127.0.0.1:8081)
      #[arg(short, long, default_value = "127.0.0.1:8081")]
      addr: String,

      /// Path to the certificate file (DER or PEM)
      #[arg(short, long, default_value = "/Users/buste/RustroverProjects/quic_demo/certs/cert.der")]
      cert: String,

      /// Path to the private key file (DER or PEM)
      #[arg(short, long, default_value = "/Users/buste/RustroverProjects/quic_demo/certs/key.der")]
      key: String,
  }

  async fn run_tls_server(addr: &str, cert_path: &str, key_path: &str) -> Result<(), Box<dyn Error + Send + Sync>>;
  async fn handle_tls_connection(tls_stream: tokio_rustls::server::TlsStream<TcpStream>, addr: SocketAddr);
  ```
- **核心逻辑**:
  - 使用 `tokio` 进行异步 I/O 操作。
  - 使用 `rustls` 和 `tokio-rustls` 处理 TLS 连接。
  - 加载证书和密钥以配置 TLS 服务器。
  - 为每个连接生成一个任务来处理请求。

### 2. 客户端 (`src/bin/client.rs`)

- **功能**: 连接到指定的服务器地址，并发地发送多个请求，并收集性能统计数据。
- **启动**: 通过命令行参数指定服务器地址 (`--addr`)、并发任务数 (`--concurrency`) 和每个任务的请求数 (`--requests`)。还可以指定 CA 证书路径 (`--ca-cert`) 和 TLS 服务器名称 (`--server-name`)。
  ```rust
  // Example structure from client.rs
  struct Args {
      /// Server address to connect to (e.g., 127.0.0.1:8081)
      #[arg(short, long, default_value = "127.0.0.1:8081")]
      addr: String,

      /// Number of concurrent client tasks
      #[arg(short, long, default_value_t = 10)]
      concurrency: usize,

      /// Number of requests per task
      #[arg(short, long, default_value_t = 1000)] // Corrected default value based on file content
      requests: u32,

      /// TLS server name for SNI (use 'localhost' for self-signed certs)
      #[arg(long, default_value = "localhost")]
      server_name: String, // Corrected field name based on file content

      /// Optional path to the CA certificate file (PEM format)
      #[arg(long)]
      ca_cert: Option<String>,
  }

  async fn run_concurrent_benchmark_tls(
      server_addr_str: &str,
      tls_server_name_str: &str,
      ca_cert_path: Option<&str>,
      request: MyRequest,
      concurrent_tasks: usize,
      requests_per_task: u32,
  ) -> Result<BenchmarkStats, Box<dyn Error + Send + Sync>>;

  async fn run_single_tls_task(
      server_addr: SocketAddr,
      tls_connector: Arc<TlsConnector>,
      tls_server_name: Arc<rustls::pki_types::ServerName<'static>>,
      request_template: Arc<MyRequest>,
      num_requests: u32,
  ) -> Result<(u32, u32, Vec<f64>), Box<dyn Error + Send + Sync>>; // Corrected return type based on file content
  ```
- **核心逻辑**:
  - 使用 `tokio` 进行异步操作和任务管理。
  - 使用 `rustls` 和 `tokio-rustls` 建立 TLS 连接。
  - 可以配置 CA 证书进行服务器验证，或使用不安全的验证器（`NoServerVerification`）跳过验证。
  - 创建多个并发任务，每个任务发送指定数量的请求。
  - 收集每个请求的延迟数据，并计算总体统计信息（成功/失败次数、平均/最小/最大延迟、QPS）。

### 3. 共享库 (`src/lib.rs`)

- **功能**: 提供客户端和服务器共用的数据结构、TLS 配置函数和辅助模块。
- **主要内容**:
  - **数据结构**:
    ```rust
    pub struct MyRequest {
        pub action: String,
        // Potentially other fields
    }

    pub struct MyResponse {
        pub result: String,
        // Potentially other fields
    }

    pub struct BenchmarkStats {
        pub total: u32,
        pub success: u32,
        pub fail: u32,
        pub avg_latency_ms: f64,
        pub min_ms: f64,
        pub max_ms: f64,
        pub qps: f64,
    }
    ```
  - **TLS 配置**:
    - `load_certs_and_key()`: 从文件加载证书和密钥。
    - `create_server_config()`: 创建服务器端 TLS 配置。
    - `create_client_config()`: 创建客户端 TLS 配置，支持可选的 CA 证书验证。
  - **不安全验证器 (`danger::NoServerVerification`)**:
    - 提供一个实现了 `rustls::client::danger::ServerCertVerifier` 的结构体，用于在客户端跳过服务器证书验证。这在测试或特定内部网络环境中可能有用，但在生产环境中通常不推荐。
    ```rust
    // Simplified structure from lib.rs
    pub mod danger {
        // ... imports ...
        #[derive(Debug)]
        pub struct NoServerVerification {
            provider: Arc<CryptoProvider>,
        }

        impl NoServerVerification {
            pub fn new(provider: Arc<CryptoProvider>) -> Self { /* ... */ }
        }

        impl rustls::client::danger::ServerCertVerifier for NoServerVerification {
            // Methods that effectively bypass verification
            fn verify_server_cert(/* ... */) -> Result<ServerCertVerified, Error> {
                Ok(ServerCertVerified::assertion())
            }
            // ... other required methods using the provider ...
        }
    }
    ```

## 工作流程

1.  **启动服务器**: 运行 `server` 二进制文件，指定监听地址、证书和密钥路径。服务器开始监听传入的 TLS 连接。
2.  **启动客户端**: 运行 `client` 二进制文件，指定服务器地址、并发级别、请求数量等参数。
3.  **建立连接**: 客户端根据配置（是否提供 CA 证书）创建 TLS 配置，并尝试连接到服务器。
4.  **发送请求**: 客户端启动多个并发任务，每个任务通过建立的 TLS 连接向服务器发送 `MyRequest` 类型的请求（当前示例为 `"ping_tls"`）。
5.  **处理请求**: 服务器接收到请求，处理它（当前示例是回显 action），并将 `MyResponse` 发送回客户端。
6.  **收集统计**: 客户端记录每个请求的成功/失败状态和响应时间。
7.  **生成报告**: 所有任务完成后，客户端计算并打印 `BenchmarkStats`，包括总请求数、成功/失败数、延迟统计和 QPS。

## 构建与运行 (示例)

```bash
# 构建项目
cargo build --release

# 启动服务器 (使用默认证书路径，确保证书存在或修改默认路径)
./target/release/server --addr 127.0.0.1:8081

# 在另一个终端启动客户端 (连接到服务器, 10个并发任务, 每个任务1000个请求, 使用默认localhost SNI)
# 默认情况下不验证服务器证书 (INSECURE)
./target/release/client --addr 127.0.0.1:8081 --concurrency 10 --requests 1000

# 启动客户端并使用 CA 证书进行服务器验证:
# ./target/release/client --addr 127.0.0.1:8081 --ca-cert /path/to/ca.pem --server-name your.server.domain.com
```

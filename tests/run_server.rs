use assert_matches::assert_matches;
use hickory_proto::xfer::Protocol;
use hickory_resolver::Resolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::op::ResponseCode;
use rand::Rng;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::panic::UnwindSafe;
use std::path::PathBuf;
use std::time::Duration;
use tempfile::NamedTempFile;

lazy_static::lazy_static! {
    static ref COMPILED_BINARY_PATH: PathBuf = assert_cmd::cargo::cargo_bin("dns-firewall");
}

/// The given test closure must accept ephemeral server port as argument
fn with_server(acl: &str, test: impl FnOnce(u16) + UnwindSafe) {
    let mut acl_file = NamedTempFile::new().expect("Failed to create temp ACL file");
    writeln!(acl_file, "{acl}").unwrap();
    acl_file.flush().unwrap();

    let random_port = rand::rng().random_range(20_000_u16..50_000_u16);

    let mut server = std::process::Command::new(&*COMPILED_BINARY_PATH)
        .args([
            "--acl-file",
            acl_file
                .path()
                .to_str()
                .expect("Temp ACL file path has unrepresentable characters"),
            "--firewall",
            "none",
            "--upstream",
            "127.0.0.53",
            "--bind-port",
            &random_port.to_string(),
        ])
        .spawn()
        .expect("Failed to launch server");

    std::thread::sleep(Duration::from_millis(500));

    let test_result = std::panic::catch_unwind(|| test(random_port));

    let _ = server.kill();
    server.wait().expect("Failed to join server");

    test_result.expect("Test failed");
}

#[derive(Debug)]
enum ResolveResult {
    Resolved(Vec<IpAddr>),
    Empty(ResponseCode),
    #[expect(unused)] // Remove attribute once used
    Error(hickory_resolver::ResolveError),
}

impl ResolveResult {
    fn assert_refused(self) {
        assert_matches!(self, ResolveResult::Empty(ResponseCode::Refused));
    }

    fn assert_any_ip(self) {
        assert_matches!(self, ResolveResult::Resolved(v) if !v.is_empty());
    }

    fn assert_specific_ip(self, addr: &str) {
        assert_matches!(self, ResolveResult::Resolved(v) if v.len() == 1 && v[0].to_string() == addr);
    }
}

#[must_use]
async fn resolve(server_port: u16, server_protocol: Protocol, domain: &str) -> ResolveResult {
    let resolver_config = ResolverConfig::from_parts(
        None,
        vec![],
        vec![NameServerConfig {
            socket_addr: SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 53), server_port).into(),
            protocol: server_protocol,
            tls_dns_name: None,
            http_endpoint: None,
            trust_negative_responses: true,
            bind_addr: None,
        }],
    );

    let mut resolver_builder =
        Resolver::builder_with_config(resolver_config, TokioConnectionProvider::default());

    let resolver_opts = resolver_builder.options_mut();
    resolver_opts.attempts = 1;
    resolver_opts.cache_size = 0;

    let resolver = resolver_builder.build();

    match resolver.lookup_ip(domain).await {
        Ok(resolved) => ResolveResult::Resolved(resolved.iter().collect()),
        Err(e) => {
            if let hickory_resolver::ResolveErrorKind::Proto(proto_error) = e.kind() {
                if let hickory_proto::ProtoErrorKind::NoRecordsFound { response_code, .. } =
                    proto_error.kind()
                {
                    ResolveResult::Empty(*response_code)
                } else {
                    ResolveResult::Error(e)
                }
            } else {
                ResolveResult::Error(e)
            }
        }
    }
}

#[test]
fn localhost_filtering() {
    let acl = r#"
127.0.0.1 -> google.com:TCP:443
127.0.0.1 ~> www.rust-lang.org
127.0.0.1 -| refuse.me
127.0.0.1 -| block.me = 13.93.4.29
"#;

    with_server(acl, |port| {
        let rt = tokio::runtime::Runtime::new().unwrap();

        rt.block_on(async {
            resolve(port, Protocol::Udp, "example.com")
                .await
                .assert_refused();

            resolve(port, Protocol::Tcp, "example.com")
                .await
                .assert_refused();

            resolve(port, Protocol::Udp, "google.com")
                .await
                .assert_any_ip();

            resolve(port, Protocol::Tcp, "google.com")
                .await
                .assert_any_ip();

            resolve(port, Protocol::Udp, "www.rust-lang.org")
                .await
                .assert_any_ip();

            resolve(port, Protocol::Tcp, "www.rust-lang.org")
                .await
                .assert_any_ip();

            resolve(port, Protocol::Udp, "refuse.me")
                .await
                .assert_refused();

            resolve(port, Protocol::Tcp, "refuse.me")
                .await
                .assert_refused();

            resolve(port, Protocol::Udp, "block.me")
                .await
                .assert_specific_ip("13.93.4.29");

            resolve(port, Protocol::Tcp, "block.me")
                .await
                .assert_specific_ip("13.93.4.29");
        })
    })
}

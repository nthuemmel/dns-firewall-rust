mod access_logger;
mod message_processor;

use crate::access_control_tree::AccessControlTree;
use crate::firewall_backend::FirewallBackend;
use crate::program_config::ProxyServerConfig;
use crate::proxy_server::access_logger::LogEntryKind;
use crate::proxy_server::message_processor::{
    DnsMessageProcessor, ForwardedRequest, RequestReaction, ResponseReaction,
};
use anyhow::Context;
use dns_parser::ResponseCode;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{timeout, Duration};

const BUFFER_SIZE: usize = 32768;

pub struct ProxyServer {
    message_processor: DnsMessageProcessor,
    upstream_server_socket_addr: SocketAddr,
    upstream_client_init_socket_addr: SocketAddr,
    udp_server_socket: UdpSocket,
    tcp_listener: TcpListener,
    processing_limit: Arc<Semaphore>,
    timeout: Duration,
}

impl ProxyServer {
    pub async fn new(
        settings: ProxyServerConfig,
        access_control_tree: AccessControlTree,
        firewall_backend: Box<dyn FirewallBackend>,
    ) -> anyhow::Result<Arc<Self>> {
        let message_processor = DnsMessageProcessor::new(
            access_control_tree,
            chrono::Duration::seconds(settings.min_rule_time as i64),
            settings
                .max_rule_time
                .map(|v| chrono::Duration::seconds(v as i64))
                .unwrap_or_else(chrono::Duration::max_value),
            firewall_backend,
        );

        let bind_socket_addr = SocketAddr::new(settings.bind, settings.bind_port);

        let udp_server_socket = UdpSocket::bind(bind_socket_addr)
            .await
            .with_context(|| format!("Failed to bind UDP server socket at {}", bind_socket_addr))?;

        let tcp_listener = TcpListener::bind(bind_socket_addr)
            .await
            .with_context(|| format!("Failed to bind TCP server socket at {}", bind_socket_addr))?;

        Ok(Arc::new(Self {
            message_processor,
            upstream_server_socket_addr: SocketAddr::new(settings.upstream, settings.upstream_port),
            upstream_client_init_socket_addr: SocketAddr::new(
                if settings.upstream.is_ipv4() {
                    Ipv4Addr::new(0, 0, 0, 0).into()
                } else {
                    Ipv6Addr::from_str("::").unwrap().into()
                },
                0,
            ),
            udp_server_socket,
            tcp_listener,
            processing_limit: Arc::new(Semaphore::new(settings.max_connections as usize)),
            timeout: Duration::from_secs(settings.timeout as u64),
        }))
    }

    pub async fn run(self: Arc<Self>) -> anyhow::Result<()> {
        // The `run_xxx_server()` methods only return on error.
        // This method returns the first error encountered.
        tokio::select! {
            r = self.run_udp_server() => r,
            r = self.run_tcp_server() => r,
        }
    }

    async fn run_udp_server(self: &Arc<Self>) -> anyhow::Result<()> {
        loop {
            let request_permit = self.processing_limit.clone().acquire_owned().await.unwrap();

            // Receive request
            let mut buffer = vec![0u8; BUFFER_SIZE];
            let (len, client_address) = self.udp_server_socket.recv_from(&mut buffer).await?;
            buffer.truncate(len);

            // Process request
            let proxy = self.clone();
            tokio::spawn(async move {
                proxy
                    .process_udp_request(request_permit, client_address, buffer)
                    .await
            });
        }
    }

    async fn process_udp_request(
        &self,
        _request_permit: OwnedSemaphorePermit,
        client_address: SocketAddr,
        mut buffer: Vec<u8>,
    ) {
        let reaction = self
            .message_processor
            .process_client_request(client_address.ip(), &mut buffer);

        match reaction {
            RequestReaction::Discard => return,

            RequestReaction::ForwardToUpstream { forwarded_request } => {
                if let Err(e) = async {
                    let upstream_socket =
                        UdpSocket::bind(&self.upstream_client_init_socket_addr).await?;

                    timeout(
                        self.timeout,
                        upstream_socket.send_to(&buffer, &self.upstream_server_socket_addr),
                    )
                    .await
                    .map_err(|_| anyhow::anyhow!("Sending request to upstream timed out"))?
                    .context("Sending request to upstream failed")?;

                    loop {
                        buffer.resize(buffer.capacity(), 0u8);
                        let (len, server_address) =
                            timeout(self.timeout, upstream_socket.recv_from(&mut buffer))
                                .await
                                .map_err(|_| {
                                    anyhow::anyhow!("Receiving response from upstream timed out")
                                })?
                                .context("Receiving response from upstream failed")?;
                        buffer.truncate(len);

                        if server_address != self.upstream_server_socket_addr {
                            continue;
                        }

                        let reaction = self
                            .message_processor
                            .process_upstream_response(
                                client_address.ip(),
                                &mut buffer,
                                &forwarded_request,
                            )
                            .await;

                        match reaction {
                            ResponseReaction::Discard => continue,
                            ResponseReaction::ForwardToClient => break,
                        }
                    }

                    Ok::<(), anyhow::Error>(())
                }
                .await
                {
                    self.handle_upstream_error(client_address, &forwarded_request, e, &mut buffer);
                }
            }

            RequestReaction::RespondToClient => (),
        }

        // Silently ignore send errors
        let _ = timeout(
            self.timeout,
            self.udp_server_socket.send_to(&buffer, &client_address),
        )
        .await;
    }

    async fn run_tcp_server(self: &Arc<Self>) -> anyhow::Result<()> {
        loop {
            let connection_permit = self.processing_limit.clone().acquire_owned().await.unwrap();

            // Accept connection
            let (stream, client_address) = self.tcp_listener.accept().await?;

            // Process request
            let proxy = self.clone();
            tokio::spawn(async move {
                proxy
                    .process_tcp_connection(connection_permit, stream, client_address)
                    .await
            });
        }
    }

    async fn process_tcp_connection(
        &self,
        _connection_permit: OwnedSemaphorePermit,
        mut client_stream: TcpStream,
        client_address: SocketAddr,
    ) {
        let mut buffer = vec![0u8; BUFFER_SIZE];
        let mut upstream = None;

        loop {
            match timeout(self.timeout, async {
                let request_length = client_stream.read_u16().await?;

                if request_length as usize > buffer.capacity() {
                    self.message_processor.access_logger.log(
                        client_address.ip(),
                        LogEntryKind::RequestError,
                        None,
                        &format!(
                            "Request length ({} bytes) exceeds buffer capacity ({} bytes)",
                            request_length,
                            buffer.capacity()
                        ),
                    );
                    anyhow::bail!("Request length exceeds buffer capacity");
                }

                buffer.resize(request_length as usize, 0);
                client_stream.read_exact(&mut buffer).await?;
                Ok(())
            })
            .await
            {
                Err(_) | Ok(Err(_)) => {
                    // Either timeout or request receive error, terminate connection
                    return;
                }
                Ok(Ok(())) => (),
            }

            let reaction = self
                .message_processor
                .process_client_request(client_address.ip(), &mut buffer);

            match reaction {
                RequestReaction::Discard => return,

                RequestReaction::ForwardToUpstream { forwarded_request } => {
                    match async {
                        let upstream = self.connect_upstream_tcp_socket(&mut upstream).await?;

                        timeout(self.timeout, async {
                            upstream.write_u16(buffer.len() as u16).await?;
                            upstream.write_all(&buffer).await
                        })
                        .await
                        .map_err(|_| anyhow::anyhow!("Sending request to upstream timed out"))?
                        .context("Sending request to upstream failed")?;

                        timeout(self.timeout, async {
                            let response_length = upstream.read_u16().await?;

                            if response_length as usize > buffer.capacity() {
                                anyhow::bail!(
                                    "Response length ({} bytes) exceeds buffer capacity ({} bytes)",
                                    response_length,
                                    buffer.capacity()
                                );
                            }

                            buffer.resize(response_length as usize, 0);
                            upstream.read_exact(&mut buffer).await?;
                            Ok(())
                        })
                        .await
                        .map_err(|_| anyhow::anyhow!("Receiving response from upstream timed out"))?
                        .context("Receiving response from upstream failed")?;

                        Ok(self
                            .message_processor
                            .process_upstream_response(
                                client_address.ip(),
                                &mut buffer,
                                &forwarded_request,
                            )
                            .await)
                    }
                    .await
                    {
                        Ok(ResponseReaction::Discard) => {
                            // The response did not match the request - there is no good cause of
                            // action here, we just terminate the connection
                            return;
                        }
                        Ok(ResponseReaction::ForwardToClient) => (),
                        Err(e) => {
                            self.handle_upstream_error(
                                client_address,
                                &forwarded_request,
                                e,
                                &mut buffer,
                            );
                        }
                    }
                }

                RequestReaction::RespondToClient => (),
            }

            match timeout(self.timeout, async {
                client_stream.write_u16(buffer.len() as u16).await?;
                client_stream.write_all(&buffer).await
            })
            .await
            {
                Ok(Ok(())) => (),
                Err(_) | Ok(Err(_)) => {
                    // Timeout or sending response failed, terminate connection
                    return;
                }
            }
        }
    }

    #[allow(clippy::needless_lifetimes)] // false positive
    async fn connect_upstream_tcp_socket<'a>(
        &self,
        stream: &'a mut Option<TcpStream>,
    ) -> anyhow::Result<&'a mut TcpStream> {
        if let Some(stream) = stream {
            return Ok(stream);
        }

        let new_stream = timeout(
            self.timeout,
            TcpStream::connect(self.upstream_server_socket_addr),
        )
        .await
        .context("TCP connect to upstream timed out")?
        .context("TCP connect to upstream failed")?;

        *stream = Some(new_stream);
        Ok(stream.as_mut().unwrap())
    }

    /// Logs error & builds response
    fn handle_upstream_error(
        &self,
        client_address: SocketAddr,
        forwarded_request: &ForwardedRequest,
        e: anyhow::Error,
        buffer: &mut Vec<u8>,
    ) {
        self.message_processor.access_logger.log(
            client_address.ip(),
            LogEntryKind::ResponseError,
            Some(forwarded_request.original_request_header.id),
            &format!("{:#}", e),
        );
        DnsMessageProcessor::build_response(
            &forwarded_request.original_request_header,
            ResponseCode::ServerFailure,
            buffer,
        );
    }
}

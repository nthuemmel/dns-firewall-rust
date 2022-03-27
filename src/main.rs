mod access_control_list_parser;
mod access_control_tree;
mod firewall_backend;
mod program_config;
mod protocol;
mod proxy_server;

use crate::firewall_backend::iptables::IptablesFirewallBackend;
use crate::firewall_backend::noop::NoopFirewallBackend;
use crate::firewall_backend::FirewallBackend;
use crate::program_config::{FirewallKind, ProgramConfig};
use crate::proxy_server::ProxyServer;
use anyhow::Context;
use env_logger::Env;
use tokio::signal::unix::{signal, SignalKind};

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    // Parse options
    let options = ProgramConfig::parse();

    // Set up logging
    env_logger::Builder::from_env(Env::default().default_filter_or(if cfg!(debug_assertions) {
        "debug"
    } else {
        "info"
    }))
    .format_timestamp(None)
    .format_module_path(false)
    .init();

    run(options).await
}

async fn run(options: ProgramConfig) -> anyhow::Result<()> {
    let access_control_tree = access_control_list_parser::parse_file(&options.acl_file)
        .with_context(|| {
            format!(
                "Failed to parse access control list file at '{}'",
                options.acl_file.display()
            )
        })?;

    let firewall_backend: Box<dyn FirewallBackend> = match options.firewall.backend {
        FirewallKind::none => Box::new(NoopFirewallBackend::new()),
        FirewallKind::iptables => {
            let chain = options
                .firewall
                .chain
                .unwrap_or_default()
                .trim()
                .to_string();

            if chain.is_empty() {
                anyhow::bail!("Firewall chain is empty, please update your config.");
            }

            Box::new(
                IptablesFirewallBackend::new(chain)
                    .context("Failed to initialize iptables firewall backend")?,
            )
        }
    };

    let proxy_server =
        ProxyServer::new(options.proxy_server, access_control_tree, firewall_backend)
            .await
            .context("Failed to start proxy server")?;

    let mut sigint = signal(SignalKind::interrupt()).unwrap();
    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    let mut sigquit = signal(SignalKind::quit()).unwrap();

    log::info!(
        "Server started on [{}]:{}!",
        options.proxy_server.bind,
        options.proxy_server.bind_port
    );

    // Run until a fatal error is encountered or one of the specified signals are received
    (tokio::select! {
        r = proxy_server.run() => r,
        _ = sigint.recv() => Ok(()),
        _ = sigterm.recv() => Ok(()),
        _ = sigquit.recv() => Ok(()),
    })?;

    log::info!("Server stopped.");

    Ok(())
}

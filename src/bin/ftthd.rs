
use clap::{Parser, Subcommand};

use std::path::PathBuf;


fn main() {
    env_logger::init();
    let args = Cli::parse();
    let config_manager = ftthd::config::ConfigManager::new(&args.config);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        if let Err(e) = config_manager.load().await {
            log::warn!("Failed to load configuration: {:?}", e);
        }

        let config = config_manager.clone();
        tokio::spawn(async move {
            while !config_manager.is_loaded() {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let _ = config_manager.load().await;
            }

            log::info!("Configuration loaded");
        });

        // enable config reloader for daemon subcommands
        let config_reloader = config.clone();
        let enable_config_reloader = move || {
            tokio::spawn(async move {
                let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).unwrap();
                loop {
                    signal.recv().await;
                    log::info!("Received SIGHUP, reloading configuration");
                    if let Err(e) = config_reloader.load().await {
                        log::warn!("Failed to reload configuration: {:?}", e);
                    }
                }
            });
        };

        match args.subcmd {
            Command::Start => {
                enable_config_reloader();
                start(config).await;
            }

            #[allow(unreachable_patterns)]
            _ => {
                log::error!("Invalid subcommand");
            }
        }
    });
}

async fn start(config: ftthd::config::ConfigManager) {
    if !config.is_loaded() {
        log::warn!("Configuration not loaded, waiting til configured");
        config.subscribe().recv().await.unwrap();
        assert!(config.is_loaded());
    }

    let config_data = config.get().unwrap();
    log::debug!("Configuration: {:?}", config_data);
}


/// FTTHd daemon
#[derive(Debug, Clone, Parser)]
#[clap(name = "ftthd", version, about)]
pub struct Cli {
    /// Path to the configuration file
    #[clap(short, long, default_value = "/etc/ftthd.toml")]
    pub config: PathBuf,

    #[clap(subcommand)]
    pub subcmd: Command,
}

#[derive(Debug, Clone, Subcommand)]
#[non_exhaustive]
pub enum Command {
    /// start the daemon
    Start,
}

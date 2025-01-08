
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use serde::Deserialize;
use serde::Serialize;

use parking_lot::RwLock;

#[derive(Debug, Clone)]
pub struct ConfigManager {
    config_path: Arc<PathBuf>,
    config: Arc<RwLock<Option<Config>>>,
    broadcast: tokio::sync::broadcast::Sender<()>,
}

impl ConfigManager {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        let path = path.as_ref().to_path_buf();
        let config = None;
        Self {
            config_path: Arc::new(path),
            config: Arc::new(RwLock::new(config)),
            broadcast: tokio::sync::broadcast::channel(1).0,
        }
    }

    fn notify_change(&self) {
        let _ = self.broadcast.send(());
    }

    pub async fn load(&self) -> Result<(), std::io::Error> {
        tokio::task::block_in_place(|| {
            let config = Config::from_file(self.config_path.as_ref())?;
            let result = Some(config);
            let orig = std::mem::replace(&mut *self.config.write(), result.clone());
            if orig != result {
                self.notify_change();
            }
            Ok(())
        })
    }

    pub fn get(&self) -> Option<Config> {
        self.config.read().clone()
    }

    pub fn is_loaded(&self) -> bool {
        self.config.read().is_some()
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<()> {
        self.broadcast.subscribe()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Config {
    pub global: GlobalConfig,
    pub interfaces: InterfaceConfig,
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(file: P) -> Result<Self, std::io::Error> {
        let content = std::fs::read_to_string(file)?;
        let config: Config = toml::from_str(&content).map_err(|e| std::io::Error::other(e))?;
        Ok(config)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct InterfaceConfig {
    pub upstream: String,
    pub downstreams: Vec<String>,
}

impl InterfaceConfig {
    pub fn interfaces(&self) -> Vec<String> {
        let mut interfaces = std::collections::HashSet::new();
        interfaces.insert(self.upstream.clone());
        for downstream in &self.downstreams {
            interfaces.insert(downstream.clone());
        }
        interfaces.into_iter().collect()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProxyMode {
    /// NDP proxy mode
    NdpProxy,

    /// DHCPv6-PD mode
    Dhcpv6Pd,
}

impl Default for ProxyMode {
    fn default() -> Self {
        ProxyMode::NdpProxy
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct GlobalConfig {
    #[serde(default)]
    pub proxy_mode: ProxyMode,
}

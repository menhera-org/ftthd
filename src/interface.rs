
use parking_lot::RwLock;

use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::oneshot;

pub fn index_to_name(index: libc::c_uint) -> Result<String, std::io::Error> {
    let ifname_buf = [0u8; libc::IFNAMSIZ];
    let ret = unsafe { libc::if_indextoname(index, ifname_buf.as_ptr() as *mut libc::c_char) };
    if ret.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    
    let name = unsafe { std::ffi::CStr::from_ptr(ret as *const libc::c_char) };
    Ok(name.to_string_lossy().into_owned())
}

pub fn name_to_index(name: &str) -> Result<libc::c_uint, std::io::Error> {
    let index = unsafe { libc::if_nametoindex(name.as_ptr() as *const libc::c_char) };
    if index == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(index)
}

#[derive(Debug, Clone, PartialEq)]
pub struct Interface {
    pub if_index: libc::c_uint,
    pub if_name: String,
}

#[derive(Debug)]
pub(crate) struct InterfaceState {
    interfaces: RwLock<HashMap<libc::c_uint, Interface>>,
    if_by_name: RwLock<HashMap<String, libc::c_uint>>,
    link_local_addrs: RwLock<HashMap<libc::c_uint, Vec<std::net::Ipv6Addr>>>,
}

impl InterfaceState {
    pub fn new() -> Self {
        Self {
            interfaces: RwLock::new(HashMap::new()),
            if_by_name: RwLock::new(HashMap::new()),
            link_local_addrs: RwLock::new(HashMap::new()),
        }
    }

    pub fn if_indexes(&self) -> Vec<libc::c_uint> {
        self.interfaces.read().keys().map(|v| *v).collect()
    }
}

#[derive(Debug, Clone)]
pub struct InterfaceStateManager {
    state: Arc<InterfaceState>,
    _updater_join: crate::util::BoxedDropDetector,
}

impl InterfaceStateManager {
    pub async fn new() -> Self {
        let state = Arc::new(InterfaceState::new());
        let state_clone = state.clone();
        let (init_sender, init_receiver) = oneshot::channel();
        let join = tokio::spawn(async move {
            let rtnl = crate::rtnl::RtnetlinkConnection::new().await.unwrap();
            let mut link_manager = rtnl.link();
            let addr_manager = rtnl.address();

            let once = std::sync::Once::new();
            let mut once_closure = Some(move || {
                let _ = init_sender.send(());
            });

            loop {
                let interfaces = match link_manager.get_all().await {
                    Ok(interfaces) => interfaces,
                    Err(e) => {
                        log::error!("failed to get interfaces: {}", e);
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        continue;
                    }
                };
                let mut interfaces_map = HashMap::new();
                let mut if_by_name = HashMap::new();
                for interface in interfaces {
                    if_by_name.insert(interface.if_name.clone(), interface.if_index);
                    interfaces_map.insert(interface.if_index, interface);
                }
                *state_clone.interfaces.write() = interfaces_map;
                *state_clone.if_by_name.write() = if_by_name;

                let mut link_local_addrs = HashMap::new();
                let indexes = state_clone.if_indexes();
                for if_index in indexes {
                    let addrs = match addr_manager.get_v6(if_index, crate::rtnl::addr::V6AddressRequestScope::LinkLocal).await {
                        Ok(addrs) => addrs,
                        Err(e) => {
                            log::error!("failed to get link-local addresses for interface {}: {}", if_index, e);
                            continue;
                        }
                    };
                    link_local_addrs.insert(if_index, addrs);
                }
                *state_clone.link_local_addrs.write() = link_local_addrs;

                if let Some(closure) = once_closure.take() {
                    once.call_once(closure);
                }

                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });

        let updater_join = crate::util::DropDetector::new_boxed(move || {
            let _ = join.abort();
        });

        let _ = init_receiver.await;
        Self { state, _updater_join: updater_join }
    }

    pub fn get_all_indexes(&self) -> Vec<libc::c_uint> {
        self.state.if_indexes()
    }

    pub fn get_index_by_name(&self, name: &str) -> Option<libc::c_uint> {
        self.state.if_by_name.read().get(name).map(|v| *v)
    }

    pub fn get(&self, if_index: libc::c_uint) -> Option<Interface> {
        self.state.interfaces.read().get(&if_index).map(|v| v.clone())
    }

    pub fn get_name_by_index(&self, if_index: libc::c_uint) -> Option<String> {
        self.state.interfaces.read().get(&if_index).map(|v| v.if_name.clone())
    }

    pub fn get_link_local_addrs(&self, if_index: libc::c_uint) -> Option<Vec<std::net::Ipv6Addr>> {
        self.state.link_local_addrs.read().get(&if_index).map(|v| v.clone())
    }

    pub fn get_link_local_addr(&self, if_index: libc::c_uint) -> Option<std::net::Ipv6Addr> {
        self.state.link_local_addrs.read().get(&if_index).and_then(|v| v.first().cloned())
    }
}

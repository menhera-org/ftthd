
use crate::config::InterfaceConfig;
use crate::interface::InterfaceId;
use crate::icmp6::AsyncIcmp6Socket;
use crate::icmp6::socket;

use std::collections::HashMap;
use std::collections::HashSet;
use std::net::Ipv6Addr;

#[derive(Debug, Clone)]
pub struct MldSubscription {
    pub timestamp: u64,
    pub group_addr: Ipv6Addr,
    pub source_addrs: HashSet<Ipv6Addr>,
}

#[derive(Debug)]
pub struct MldSubscriptionManager {
    socket: AsyncIcmp6Socket,
    subscriptions: HashMap<InterfaceId, HashMap<Ipv6Addr, MldSubscription>>,
    vifs: HashMap<InterfaceId, socket::mifi_t>,
    last_vifd: socket::mifi_t,
    parent_if_index: InterfaceId,
}

impl MldSubscriptionManager {
    pub fn new(socket: AsyncIcmp6Socket, interface_config: crate::config::InterfaceConfig) -> Self {
        let parent_if_index = crate::interface::name_to_index(&interface_config.upstream).unwrap();
        let downstreams = interface_config.downstreams.iter()
            .map(|name| crate::interface::name_to_index(name))
            .filter(|id| id.is_ok())
            .map(|id| id.unwrap())
            .collect::<Vec<_>>();

        let mut instance = Self {
            socket,
            subscriptions: HashMap::new(),
            vifs: HashMap::new(),
            last_vifd: 0,
            parent_if_index,
        };

        instance.add_if(parent_if_index).unwrap();
        for if_index in downstreams {
            instance.add_if(if_index).unwrap();
        }

        instance
    }

    pub fn add_if(&mut self, if_index: InterfaceId) -> Result<(), std::io::Error> {
        if self.vifs.contains_key(&if_index) {
            return Ok(());
        }
        self.last_vifd += 1;

        self.socket.multicast_add_vif(self.last_vifd, if_index)?;
        self.vifs.insert(if_index, self.last_vifd);
        Ok(())
    }

    pub fn remove_if(&mut self, if_index: InterfaceId) -> Result<(), std::io::Error> {
        if let Some(vifd) = self.vifs.get(&if_index) {
            self.socket.multicast_del_vif(*vifd)?;
        }
        self.vifs.remove(&if_index);
        Ok(())
    }

    fn get_vifd(&self, if_index: InterfaceId) -> Option<socket::mifi_t> {
        self.vifs.get(&if_index).cloned()
    }

    pub fn get_subscribed_interfaces(&self, group_addr: std::net::Ipv6Addr) -> HashSet<InterfaceId> {
        self.subscriptions.iter()
            .filter(|(_, subscriptions)| subscriptions.contains_key(&group_addr))
            .map(|(if_index, _)| *if_index)
            .collect()
    }

    pub fn add_subscription(&mut self, if_index: InterfaceId, group_addr: std::net::Ipv6Addr, source_addrs: HashSet<Ipv6Addr>) {
        let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

        let source_addrs = {
            let subscription = self.subscriptions
                .entry(if_index)
                .or_insert(HashMap::new())
                .entry(group_addr)
                .or_insert(MldSubscription {
                    timestamp: 0,
                    group_addr,
                    source_addrs: HashSet::new(),
                });
            
            if subscription.timestamp != 0 {
                return;
            }

            subscription.timestamp = timestamp;

            for source_addr in source_addrs {
                subscription.source_addrs.insert(source_addr);
            }

            let source_addrs = subscription.source_addrs.clone();

            source_addrs
        };

        let parent = self.get_vifd(self.parent_if_index).unwrap();
        let output = self.get_subscribed_interfaces(group_addr).iter()
            .filter_map(|if_index| self.get_vifd(*if_index))
            .collect::<Vec<_>>();
        
        if source_addrs.is_empty() {
            let src = Ipv6Addr::UNSPECIFIED;
            if let Err(e) = self.socket.multicast_add_mroute(parent, output, group_addr, src) {
                log::error!("failed to add mroute: {}", e);
            }
            return;
        }
        
        for src in source_addrs {
            if let Err(e) = self.socket.multicast_add_mroute(parent, output.clone(), group_addr, src) {
                log::error!("failed to add mroute: {}", e);
            }
        }
    }

    pub fn remove_old_subscriptions(&mut self, timeout: u64) {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        for if_index in self.subscriptions.keys().cloned().collect::<Vec<_>>() {
            let subscriptions = self.subscriptions.get_mut(&if_index).unwrap();
            for (group_addr, subscription) in subscriptions.clone().iter() {
                if now - subscription.timestamp > timeout {
                    subscriptions.remove(group_addr);
                    let parent = self.vifs.get(&self.parent_if_index).cloned().unwrap();

                    if subscription.source_addrs.is_empty() {
                        let src = Ipv6Addr::UNSPECIFIED;
                        if let Err(e) = self.socket.multicast_del_mroute(parent, *group_addr, src) {
                            log::error!("failed to del mroute: {}", e);
                        }
                        continue;
                    }

                    let _ = self.socket.multicast_del_mroute(parent, *group_addr, Ipv6Addr::UNSPECIFIED);

                    for src in subscription.source_addrs.iter() {
                        if let Err(e) = self.socket.multicast_del_mroute(parent, *group_addr, *src) {
                            log::error!("failed to del mroute: {}", e);
                        }
                    }
                }
            }
        }

        self.subscriptions.retain(|_, subscriptions| !subscriptions.is_empty());
    }

    pub fn get_groups(&self) -> HashSet<Ipv6Addr> {
        self.subscriptions.iter().flat_map(|(_, subscriptions)| subscriptions.keys().cloned()).collect()
    }

    pub fn get_source_addresses(&self, group_addr: Ipv6Addr) -> HashSet<Ipv6Addr> {
        self.subscriptions.iter().flat_map(|(_, subscriptions)| {
            subscriptions.iter().filter_map(|(addr, subscription)| {
                if *addr == group_addr {
                    Some(subscription.source_addrs.clone())
                } else {
                    None
                }
            })
        }).flatten().collect()
    }
}

pub fn is_solicited_node_address(addr: &std::net::Ipv6Addr) -> bool {
    let solicited_node_prefix: Ipv6Addr = "ff02::1:ff00:0".parse().unwrap();
    let prefix = u128::from_be_bytes(solicited_node_prefix.octets());
    let wildcard_mask: u128 = 0xffffff;
    let addr = u128::from_be_bytes(addr.octets());
    (addr & !wildcard_mask) == prefix
}

#[derive(Debug)]
pub struct NdpMulticastManager {
    socket: AsyncIcmp6Socket,
    subscriptions: HashMap<Ipv6Addr, HashMap<InterfaceId, u64>>,
    interface_ids: HashSet<InterfaceId>,
}

impl NdpMulticastManager {
    pub fn new(socket: AsyncIcmp6Socket, interface_config: InterfaceConfig) -> Self {
        Self {
            socket,
            subscriptions: HashMap::new(),
            interface_ids: interface_config.interfaces().iter()
                .map(|name| crate::interface::name_to_index(name))
                .filter(|id| id.is_ok())
                .map(|id| id.unwrap())
                .collect(),
        }
    }

    pub fn add_subscription(&mut self, solicited_node_addr: Ipv6Addr, if_index: InterfaceId) {
        let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let prev = self.subscriptions.entry(solicited_node_addr).or_insert(HashMap::new()).insert(if_index, timestamp);
        if prev.is_some() {
            return;
        }

        let mut ifs = self.interface_ids.clone();
        ifs.remove(&if_index);

        for if_id in ifs {
            if let Err(e) = self.socket.join_multicast(solicited_node_addr, if_id) {
                log::error!("failed to join multicast: {}", e);
            }
        }
    }

    pub fn remove_old_subscriptions(&mut self, timeout: u64) {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        for solicited_node_addr in self.subscriptions.keys().cloned().collect::<Vec<_>>() {
            let subscriptions = self.subscriptions.get_mut(&solicited_node_addr).unwrap();
            for (if_index, timestamp) in subscriptions.clone().iter() {
                if now - *timestamp > timeout {
                    subscriptions.remove(if_index);
                    if subscriptions.is_empty() {
                        if let Err(e) = self.socket.leave_multicast(solicited_node_addr, InterfaceId::UNSPECIFIED) {
                            log::error!("failed to leave multicast: {}", e);
                        }
                    }
                }
            }
        }

        self.subscriptions.retain(|_, subscriptions| !subscriptions.is_empty());
    }
}

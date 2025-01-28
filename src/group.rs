
use crate::interface::InterfaceId;

use std::collections::HashMap;
use std::collections::HashSet;
use std::net::Ipv6Addr;

pub struct MldSource {
    source_addr: std::net::Ipv6Addr,
    source_timer: u64,
}

pub type MldSources = HashMap<std::net::Ipv6Addr, MldSource>;

pub enum MldMenbershipState {
    Include { include: MldSources },
    Exclude { include: MldSources, exclude: MldSources },
}

pub struct MldMembership {
    group_addr: std::net::Ipv6Addr,
    state: MldMenbershipState,
}

#[derive(Debug)]
pub struct MldSubscription {
    pub timestamp: u64,
    pub group_addr: Ipv6Addr,
}

#[derive(Debug)]
pub struct MldSubscriptionManager {
    subscriptions: HashMap<InterfaceId, HashMap<Ipv6Addr, MldSubscription>>,
}

impl MldSubscriptionManager {
    pub fn new() -> Self {
        Self {
            subscriptions: HashMap::new(),
        }
    }

    pub fn add_subscription(&mut self, if_index: InterfaceId, group_addr: std::net::Ipv6Addr) {
        let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let subscription = MldSubscription {
            timestamp,
            group_addr,
        };
        self.subscriptions.entry(if_index).or_insert(HashMap::new()).insert(group_addr, subscription);
    }

    pub fn remove_old_subscriptions(&mut self, timeout: u64) {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        for (_, subscriptions) in self.subscriptions.iter_mut() {
            subscriptions.retain(|_, subscription| now - subscription.timestamp <= timeout);
        }
    }

    pub fn get_groups(&self) -> HashSet<Ipv6Addr> {
        self.subscriptions.iter().flat_map(|(_, subscriptions)| subscriptions.keys().cloned()).collect()
    }
}

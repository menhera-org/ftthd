
use crate::interface::InterfaceId;

use std::fmt::Debug;

#[derive(Debug)]
pub struct PacketInfo {
    /// source address for sending, or destination address for receiving
    pub addr: std::net::Ipv6Addr,

    /// interface index where the packet is sent or received
    pub if_index: InterfaceId,
}

#[derive(Debug, Clone, Copy)]
pub struct PacketHopLimit {
    pub hop_limit: u8,
}

#[derive(Debug)]
pub struct PacketHopByHop {
    /// hop-by-hop options
    pub hop_by_hop: Vec<u8>,
}

pub struct Packet {
    /// destination address for sending, or source address for receiving
    pub target_addr: std::net::Ipv6Addr,

    /// packet data
    pub data: [u8; 65536],

    /// length of packet data
    pub data_len: usize,

    /// packet information
    pub info: Option<PacketInfo>,

    /// hop limit
    pub hop_limit: Option<PacketHopLimit>,

    /// hop-by-hop options
    pub hop_by_hop: Option<PacketHopByHop>,
}

impl Packet {
    pub fn new() -> Self {
        Self {
            target_addr: std::net::Ipv6Addr::UNSPECIFIED,
            data: [0; 65536],
            data_len: 0,
            info: None,
            hop_limit: None,
            hop_by_hop: None,
        }
    }

    pub fn data(&self) -> &[u8] {
        let len = self.data_len;
        if len > self.data.len() {
            &self.data
        } else {
            &self.data[..len]
        }
    }
}

impl Debug for Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("Packet");
        let mut debug = debug.field("target_addr", &self.target_addr)
            .field("data_len", &self.data_len);
        if let Some(info) = &self.info {
            debug = debug.field("info", &info);
        }
        if let Some(hop_limit) = &self.hop_limit {
            debug = debug.field("hop_limit", &hop_limit);
        }
        if let Some(hop_by_hop) = &self.hop_by_hop {
            debug = debug.field("hop_by_hop", &hop_by_hop);
        }
        debug.finish()
    }
}

#[non_exhaustive]
#[derive(Debug)]
pub enum PacketExtension {
    SourceAddress(std::net::Ipv6Addr),
    DestinationAddress(std::net::Ipv6Addr),
    TargetInterface(libc::c_uint),
}

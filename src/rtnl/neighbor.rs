
use crate::interface::InterfaceId;

#[allow(dead_code)]
pub struct NeighborManager {
    handle: rtnetlink::NeighbourHandle,
}

impl NeighborManager {
    pub(crate) fn new(handle: &super::RtnetlinkConnection) -> Self {
        Self { handle: handle.handle.neighbours() }
    }

    pub async fn proxy_add(&self, if_index: InterfaceId, dst: std::net::IpAddr) -> Result<(), std::io::Error> {
        let if_index = if_index.inner_unchecked();
        let req = self.handle.add(if_index, dst).flags(vec![netlink_packet_route::neighbour::NeighbourFlag::Proxy]);
        req.execute().await.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    pub async fn proxy_delete(&self, if_index: InterfaceId, dst: std::net::IpAddr) -> Result<(), std::io::Error> {
        let if_index = if_index.inner_unchecked();
        let mut neigh_msg = netlink_packet_route::neighbour::NeighbourMessage::default();
        neigh_msg.header.family = match dst {
            std::net::IpAddr::V4(_) => netlink_packet_route::AddressFamily::Inet,
            std::net::IpAddr::V6(_) => netlink_packet_route::AddressFamily::Inet6,
        };
        neigh_msg.header.ifindex = if_index;
        neigh_msg.header.flags = vec![netlink_packet_route::neighbour::NeighbourFlag::Proxy];
        neigh_msg.attributes.push(netlink_packet_route::neighbour::NeighbourAttribute::Destination(
            match dst {
                std::net::IpAddr::V4(v4) => netlink_packet_route::neighbour::NeighbourAddress::Inet(v4),
                std::net::IpAddr::V6(v6) => netlink_packet_route::neighbour::NeighbourAddress::Inet6(v6),
            },
        ));
        let req = self.handle.del(neigh_msg);
        req.execute().await.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

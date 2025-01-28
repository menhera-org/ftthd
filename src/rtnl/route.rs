
use crate::interface::InterfaceId;

#[allow(dead_code)]
pub struct RouteManager {
    handle: rtnetlink::RouteHandle,
}

impl RouteManager {
    pub(crate) fn new(handle: &super::RtnetlinkConnection) -> Self {
        Self { handle: handle.handle.route() }
    }

    pub async fn add_v6(&self, if_index: InterfaceId, dst: std::net::Ipv6Addr, prefix_len: u8, gateway: Option<std::net::Ipv6Addr>) -> Result<(), std::io::Error> {
        let if_index = if_index.inner_unchecked();
        let mut req = self.handle.add().v6().destination_prefix(dst, prefix_len);
        if let Some(gateway) = gateway {
            req = req.gateway(gateway);
        }
        if if_index != 0 {
            req = req.output_interface(if_index);
        }
        req.execute().await.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    pub async fn delete_v6(&self, if_index: InterfaceId, dst: std::net::Ipv6Addr, prefix_len: u8, gateway: Option<std::net::Ipv6Addr>) -> Result<(), std::io::Error> {
        let if_index = if_index.inner_unchecked();
        let mut route_msg = netlink_packet_route::route::RouteMessage::default();
        route_msg.header.address_family = netlink_packet_route::AddressFamily::Inet6;
        route_msg.header.destination_prefix_length = prefix_len;
        route_msg.header.scope = if dst.is_unicast_link_local() {
            netlink_packet_route::route::RouteScope::Link
        } else {
            netlink_packet_route::route::RouteScope::Universe
        };
        route_msg.attributes.push(netlink_packet_route::route::RouteAttribute::Destination(netlink_packet_route::route::RouteAddress::Inet6(dst)));
        if let Some(gateway) = gateway {
            route_msg.attributes.push(netlink_packet_route::route::RouteAttribute::Gateway(netlink_packet_route::route::RouteAddress::Inet6(gateway)));
        }
        if if_index != 0 {
            route_msg.attributes.push(netlink_packet_route::route::RouteAttribute::Oif(if_index));
        }
        self.handle.del(route_msg).execute().await.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

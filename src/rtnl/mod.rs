
#![allow(dead_code)]

pub mod addr;
pub mod link;

pub struct RtnetlinkConnection {
    pub(crate) handle: rtnetlink::Handle,
    receiver: futures::channel::mpsc::UnboundedReceiver<(netlink_packet_core::NetlinkMessage<netlink_packet_route::RouteNetlinkMessage>, netlink_proto::sys::SocketAddr)>,
}

impl RtnetlinkConnection {
    pub async fn new() -> Result<Self, std::io::Error> {
        let (connection, handle, receiver) = {
            let (connection, handle, receiver) = rtnetlink::new_connection()?;
            (connection, handle, receiver)
        };

        tokio::spawn(connection);

        Ok(Self { handle, receiver })
    }

    pub fn address(&self) -> addr::AddressManager {
        addr::AddressManager::new(&self)
    }

    pub fn link(&self) -> link::LinkManager {
        link::LinkManager::new(&self)
    }
}

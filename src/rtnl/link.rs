
use futures::TryStreamExt;

use crate::interface::Interface;

pub struct LinkManager {
    handle: rtnetlink::LinkHandle,
}

impl LinkManager {
    pub(crate) fn new(handle: &super::RtnetlinkConnection) -> Self {
        Self { handle: handle.handle.link() }
    }

    pub async fn get_all(&mut self) -> Result<Vec<Interface>, std::io::Error> {
        let mut interfaces = Vec::new();
        let response = self.handle.get().execute();
        futures::pin_mut!(response);
        while let Some(response) = response.try_next().await.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))? {
            let if_index = response.header.index;
            let mut if_name = None;
            for link in response.attributes.iter() {
                match link {
                    netlink_packet_route::link::LinkAttribute::IfName(name) => {
                        if_name = Some(name.clone());
                    }
                    _ => {}
                }
            }

            if if_index == 0 || if_name.is_none() {
                continue;
            }

            interfaces.push(Interface { if_index, if_name: if_name.unwrap() });
        }
        Ok(interfaces)
    }

    pub async fn get(&mut self, if_index: std::ffi::c_uint) -> Result<Option<Interface>, std::io::Error> {
        let response = self.handle.get().match_index(if_index).execute();
        futures::pin_mut!(response);
        while let Some(response) = response.try_next().await.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))? {
            let mut if_name = None;
            for link in response.attributes.iter() {
                match link {
                    netlink_packet_route::link::LinkAttribute::IfName(name) => {
                        if_name = Some(name.clone());
                    }
                    _ => {}
                }
            }

            if if_name.is_none() {
                continue;
            }

            return Ok(Some(Interface { if_index, if_name: if_name.unwrap() }));
        }
        Ok(None)
    }

    pub async fn get_by_name(&mut self, if_name: &str) -> Result<Option<Interface>, std::io::Error> {
        let response = self.handle.get().match_name(if_name.to_owned()).execute();
        futures::pin_mut!(response);
        while let Some(response) = response.try_next().await.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))? {
            let if_index = response.header.index;
            if if_index == 0 {
                continue;
            }

            return Ok(Some(Interface { if_index, if_name: if_name.to_string() }));
        }
        Ok(None)
    }
}

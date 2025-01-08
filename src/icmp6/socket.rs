
use super::packet;

use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

use std::ffi::c_int;
use libc::socket;
use libc::setsockopt;
use std::os::fd::AsRawFd;
use std::sync::Arc;

#[derive(Debug)]
pub struct RawIcmp6Socket {
    socket: c_int,
}

impl RawIcmp6Socket {
    pub fn new() -> Result<Self, std::io::Error> {
        let socket = unsafe { socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_ICMPV6) };
        if socket < 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self { socket })
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<(), std::io::Error> {
        let flags = unsafe { libc::fcntl(self.socket, libc::F_GETFL, 0) };
        if flags < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let oldflags = flags;

        let flags = if nonblocking {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };

        if flags == oldflags {
            return Ok(());
        }

        let code = unsafe { libc::fcntl(self.socket, libc::F_SETFL, flags) };
        if code < 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(())
    }

    unsafe fn setsockopt<T: Sized, O: SocketOpt>(&self, opt: O, optval: &T) -> Result<(), std::io::Error> {
        let level = opt.level();
        let optname = opt.optname();
        let code = unsafe {
            setsockopt(self.socket, level, optname, optval as *const _ as *const libc::c_void, std::mem::size_of::<T>() as libc::socklen_t)
        };
        if code < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn ipv6_mreq(&self, addr: std::net::Ipv6Addr) -> libc::ipv6_mreq {
        libc::ipv6_mreq {
            ipv6mr_multiaddr: libc::in6_addr { s6_addr: addr.octets() },
            ipv6mr_interface: 0,
        }
    }

    pub fn join_multicast(&self, group: std::net::Ipv6Addr) -> Result<(), std::io::Error> {
        let mreq = self.ipv6_mreq(group);
        unsafe { self.setsockopt(Ipv6Opt::IPV6_ADD_MEMBERSHIP, &mreq) }
    }

    pub fn leave_multicast(&self, group: std::net::Ipv6Addr) -> Result<(), std::io::Error> {
        let mreq = self.ipv6_mreq(group);
        unsafe { self.setsockopt(Ipv6Opt::IPV6_DROP_MEMBERSHIP, &mreq) }
    }

    pub fn set_unicast_hops(&self, hops: u32) -> Result<(), std::io::Error> {
        unsafe { self.setsockopt(Ipv6Opt::IPV6_UNICAST_HOPS, &hops) }
    }

    pub fn set_multicast_hops(&self, hops: u32) -> Result<(), std::io::Error> {
        unsafe { self.setsockopt(Ipv6Opt::IPV6_MULTICAST_HOPS, &hops) }
    }

    pub fn set_multicast_loop(&self, loopback: bool) -> Result<(), std::io::Error> {
        let loopback: c_int = if loopback { 1 } else { 0 };
        unsafe { self.setsockopt(Ipv6Opt::IPV6_MULTICAST_LOOP, &loopback) }
    }

    pub fn set_recv_pktinfo(&self, recv_pktinfo: bool) -> Result<(), std::io::Error> {
        let recv_pktinfo: c_int = if recv_pktinfo { 1 } else { 0 };
        unsafe { self.setsockopt(Ipv6Opt::IPV6_RECVPKTINFO, &recv_pktinfo) }
    }

    pub fn set_recv_hopopts(&self, recv_hopopts: bool) -> Result<(), std::io::Error> {
        let recv_hopopts: c_int = if recv_hopopts { 1 } else { 0 };
        unsafe { self.setsockopt(Ipv6Opt::IPV6_RECVHOPOPTS, &recv_hopopts) }
    }

    pub fn set_recv_hoplimit(&self, recv_hoplimit: bool) -> Result<(), std::io::Error> {
        let recv_hoplimit: c_int = if recv_hoplimit { 1 } else { 0 };
        unsafe { self.setsockopt(Ipv6Opt::IPV6_RECVHOPLIMIT, &recv_hoplimit) }
    }

    pub fn set_router_alert(&self, router_alert: u8) -> Result<(), std::io::Error> {
        let router_alert = router_alert as c_int;
        unsafe { self.setsockopt(Ipv6Opt::IPV6_ROUTER_ALERT, &router_alert) }
    }

    pub fn set_mrt_flag(&self, flag: bool) -> Result<(), std::io::Error> {
        let opt = if flag { Ipv6Opt::MRT6_INIT } else { Ipv6Opt::MRT6_DONE };
        let flag = 1;
        unsafe { self.setsockopt(opt, &flag) }
    }

    pub fn recv(&self, packet: &mut packet::Packet) -> Result<(), std::io::Error> {
        unsafe {
            let mut cmsg = [0u8; 1500];
            let mut src: libc::sockaddr_in6 = std::mem::zeroed();
            let mut info: libc::msghdr = std::mem::zeroed();
            let len = {
                info.msg_name = &mut src as *mut _ as *mut libc::c_void;
                info.msg_namelen = std::mem::size_of_val(&src) as libc::socklen_t;

                let mut iov = [std::io::IoSliceMut::new(&mut packet.data)];
                info.msg_iov = iov.as_mut_ptr() as *mut libc::iovec;
                info.msg_iovlen = iov.len();

                info.msg_control = cmsg.as_mut_ptr() as *mut libc::c_void;
                info.msg_controllen = cmsg.len() as usize;

                let code = libc::recvmsg(self.socket, &mut info, 0);
                if code < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                code
            };

            packet.data_len = len as usize;
            assert!(len <= packet.data.len() as isize);

            let src: std::net::Ipv6Addr = src.sin6_addr.s6_addr.into();
            packet.target_addr = src;

            packet.info = None;
            packet.hop_limit = None;
            packet.hop_by_hop = None;

            let mut cmsg = libc::CMSG_FIRSTHDR(&info as *const libc::msghdr).as_ref();

            #[allow(clippy::cast_ptr_alignment)]
            while let Some(chdr) = cmsg {
                let data = libc::CMSG_DATA(chdr as *const _);
                match (chdr.cmsg_level, chdr.cmsg_type) {
                    (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
                        let pktinfo = std::ptr::read_unaligned(data as *const libc::in6_pktinfo);
                        let dst: std::net::Ipv6Addr = pktinfo.ipi6_addr.s6_addr.into();
                        let ifindex = pktinfo.ipi6_ifindex;
                        packet.info = Some(packet::PacketInfo { addr: dst, if_index: ifindex });
                    }

                    (libc::IPPROTO_IPV6, libc::IPV6_HOPOPTS) => {
                        let hbh = std::slice::from_raw_parts(data, chdr.cmsg_len as usize);
                        packet.hop_by_hop = Some(packet::PacketHopByHop { hop_by_hop: hbh.to_vec() });
                    }

                    (libc::IPPROTO_IPV6, libc::IPV6_HOPLIMIT) => {
                        let hoplimit = std::ptr::read_unaligned(data as *const libc::c_int);
                        packet.hop_limit = Some(packet::PacketHopLimit { hop_limit: hoplimit as u8 });
                    }

                    _ => {
                        log::warn!(", unknown option: {:?}", chdr);
                    }
                }

                cmsg = libc::CMSG_NXTHDR(&info as *const libc::msghdr, chdr as *const _).as_ref();
            }
        }

        Ok(())
    }

    pub fn recv_parser(&self, parser: &mut super::Icmp6Parser) -> Result<(), std::io::Error> {
        self.recv(&mut parser.packet)?;
        Ok(())
    }

    pub fn send(&self, packet: &packet::Packet) -> Result<(), std::io::Error> {
        let dst = libc::sockaddr_in6 {
            sin6_family: libc::AF_INET6 as libc::sa_family_t,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: libc::in6_addr { s6_addr: packet.target_addr.octets() },
            sin6_scope_id: 0,
        };

        let len = packet.data_len;

        let mut info: libc::msghdr = unsafe { std::mem::zeroed() };
        info.msg_name = &dst as *const _ as *mut _;
        info.msg_namelen = std::mem::size_of_val(&dst) as libc::socklen_t;

        let mut iov = [libc::iovec {
            iov_base: packet.data.as_ptr() as *mut _,
            iov_len: len as libc::size_t,
        }];

        info.msg_iov = iov.as_mut_ptr() as *mut _;
        info.msg_iovlen = iov.len();

        let mut cmsg = [0u8; 1500];
        info.msg_control = cmsg.as_mut_ptr() as *mut _;
        info.msg_controllen = cmsg.len();

        let mut cmsg_len: usize = 0;

        if packet.info.is_some() || packet.hop_limit.is_some() || packet.hop_by_hop.is_some() {
            let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&info) };

            if let Some(pktinfo) = &packet.info {
                {
                    let cmsg = unsafe { cmsg.as_mut().unwrap() };
                    cmsg.cmsg_level = libc::IPPROTO_IPV6;
                    cmsg.cmsg_type = libc::IPV6_PKTINFO;
                    cmsg.cmsg_len = unsafe { libc::CMSG_LEN(std::mem::size_of::<libc::cmsghdr>() as libc::c_uint + std::mem::size_of::<libc::in6_pktinfo>() as libc::c_uint) as usize };

                    cmsg_len += cmsg.cmsg_len;
                }

                unsafe {
                    let data = libc::CMSG_DATA(cmsg) as *mut libc::in6_pktinfo;
                    (*data).ipi6_addr = libc::in6_addr { s6_addr: pktinfo.addr.octets() };
                    (*data).ipi6_ifindex = pktinfo.if_index;

                    if packet.hop_limit.is_some() || packet.hop_by_hop.is_some() {
                        cmsg = libc::CMSG_NXTHDR(&info, cmsg);
                    }
                }
            }

            if let Some(hop_limit) = &packet.hop_limit {
                {
                    let cmsg = unsafe { cmsg.as_mut().unwrap() };
                    cmsg.cmsg_level = libc::IPPROTO_IPV6;
                    cmsg.cmsg_type = libc::IPV6_HOPLIMIT;
                    cmsg.cmsg_len = unsafe { libc::CMSG_LEN(std::mem::size_of::<libc::cmsghdr>() as libc::c_uint + std::mem::size_of::<libc::c_int>() as libc::c_uint) as usize };

                    cmsg_len += cmsg.cmsg_len;
                }

                unsafe {
                    let data = libc::CMSG_DATA(cmsg) as *mut libc::c_int;
                    *data = hop_limit.hop_limit as libc::c_int;

                    if packet.hop_by_hop.is_some() {
                        cmsg = libc::CMSG_NXTHDR(&info, cmsg);
                    }
                }
            }

            if let Some(hop_by_hop) = &packet.hop_by_hop {
                {
                    let cmsg = unsafe { cmsg.as_mut().unwrap() };
                    cmsg.cmsg_level = libc::IPPROTO_IPV6;
                    cmsg.cmsg_type = libc::IPV6_HOPOPTS;
                    cmsg.cmsg_len = unsafe { libc::CMSG_LEN(std::mem::size_of::<libc::cmsghdr>() as libc::c_uint + hop_by_hop.hop_by_hop.len() as libc::c_uint) as usize };

                    cmsg_len += cmsg.cmsg_len;
                }

                unsafe {
                    let data = libc::CMSG_DATA(cmsg);
                    std::ptr::copy_nonoverlapping(hop_by_hop.hop_by_hop.as_ptr(), data, hop_by_hop.hop_by_hop.len());

                    //cmsg = libc::CMSG_NXTHDR(&info, cmsg);
                }
            }
        }

        info.msg_controllen = cmsg_len;

        let code = unsafe { libc::sendmsg(self.socket, &info, 0) };
        if code < 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(())
    }

    pub fn send_writer(&self, writer: &super::Icmp6Writer) -> Result<(), std::io::Error> {
        self.send(&writer.packet)
    }

    pub fn into_async(self) -> AsyncIcmp6Socket {
        AsyncIcmp6Socket::new(self)
    }
}

impl Drop for RawIcmp6Socket {
    fn drop(&mut self) {
        if self.socket < 0 {
            return;
        }
        unsafe { libc::close(self.socket) };
    }
}

impl AsRawFd for RawIcmp6Socket {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.socket
    }
}

#[derive(Debug, Clone)]
pub struct AsyncIcmp6Socket {
    inner: Arc<AsyncFd<RawIcmp6Socket>>,
}

impl AsyncIcmp6Socket {
    pub(crate) fn new(socket: RawIcmp6Socket) -> Self {
        socket.set_nonblocking(true).unwrap();
        let inner = Arc::new(AsyncFd::with_interest(socket, Interest::READABLE | Interest::WRITABLE).unwrap());
        Self { inner }
    }

    pub async fn recv(&self, packet: &mut packet::Packet) -> Result<(), std::io::Error> {
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| inner.get_ref().recv(packet)) {
                Ok(res) => {
                    return res;
                }

                Err(_) => continue,
            }
        }
    }

    pub async fn recv_parser(&self, parser: &mut super::Icmp6Parser) -> Result<(), std::io::Error> {
        self.recv(&mut parser.packet).await?;
        Ok(())
    }

    pub async fn send(&self, packet: &packet::Packet) -> Result<(), std::io::Error> {
        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|inner| inner.get_ref().send(packet)) {
                Ok(res) => {
                    return res;
                }

                Err(_) => continue,
            }
        }
    }

    pub async fn send_writer(&self, writer: &super::Icmp6Writer) -> Result<(), std::io::Error> {
        self.send(&writer.packet).await?;
        Ok(())
    }
}

pub trait SocketOpt {
    fn level(&self) -> c_int;
    fn optname(&self) -> c_int;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Opt(c_int);

impl SocketOpt for Ipv6Opt {
    fn level(&self) -> c_int {
        libc::IPPROTO_IPV6
    }

    fn optname(&self) -> c_int {
        self.0
    }
}

impl Ipv6Opt {
    pub const IPV6_ADD_MEMBERSHIP: Self = Self(libc::IPV6_ADD_MEMBERSHIP);
    pub const IPV6_DROP_MEMBERSHIP: Self = Self(libc::IPV6_DROP_MEMBERSHIP);
    pub const IPV6_UNICAST_HOPS: Self = Self(libc::IPV6_UNICAST_HOPS);
    pub const IPV6_MULTICAST_HOPS: Self = Self(libc::IPV6_MULTICAST_HOPS);
    pub const IPV6_MULTICAST_LOOP: Self = Self(libc::IPV6_MULTICAST_LOOP);
    pub const IPV6_RECVPKTINFO: Self = Self(libc::IPV6_RECVPKTINFO);
    pub const IPV6_HOPOPTS: Self = Self(libc::IPV6_HOPOPTS);
    pub const IPV6_HOPLIMIT: Self = Self(libc::IPV6_HOPLIMIT);
    pub const IPV6_ROUTER_ALERT: Self = Self(libc::IPV6_ROUTER_ALERT);
    pub const IPV6_MTU_DISCOVER: Self = Self(libc::IPV6_MTU_DISCOVER);
    pub const IPV6_MTU: Self = Self(libc::IPV6_MTU);
    pub const IPV6_RECVHOPOPTS: Self = Self(libc::IPV6_RECVHOPOPTS);
    pub const IPV6_RECVHOPLIMIT: Self = Self(libc::IPV6_RECVHOPLIMIT);

    const MRT6_BASE: c_int = 200;
    pub const MRT6_INIT: Self = Self(Self::MRT6_BASE + 0);
    pub const MRT6_DONE: Self = Self(Self::MRT6_BASE + 1);
    pub const MRT6_ADD_MIF: Self = Self(Self::MRT6_BASE + 2);
    pub const MRT6_DEL_MIF: Self = Self(Self::MRT6_BASE + 3);
    pub const MRT6_ADD_MFC: Self = Self(Self::MRT6_BASE + 4);
    pub const MRT6_DEL_MFC: Self = Self(Self::MRT6_BASE + 5);
    pub const MRT6_VERSION: Self = Self(Self::MRT6_BASE + 6);
    pub const MRT6_ASSERT: Self = Self(Self::MRT6_BASE + 7);
    pub const MRT6_PIM: Self = Self(Self::MRT6_BASE + 8);
    pub const MRT6_TABLE: Self = Self(Self::MRT6_BASE + 9);
    pub const MRT6_ADD_MFC_PROXY: Self = Self(Self::MRT6_BASE + 10);
    pub const MRT6_DEL_MFC_PROXY: Self = Self(Self::MRT6_BASE + 11);
    pub const MRT6_ADD_MIF_PROXY: Self = Self(Self::MRT6_BASE + 12);
}

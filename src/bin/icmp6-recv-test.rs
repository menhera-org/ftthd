
use ftthd::icmp6::socket::RawIcmp6Socket;
use ftthd::icmp6::Icmp6Packet;
use ftthd::interface::{self, InterfaceId};

use std::str::FromStr;

fn main() -> std::io::Result<()> {
    env_logger::init();
    let socket = RawIcmp6Socket::new()?;
    socket.set_recv_hoplimit(true)?;
    socket.set_recv_hopopts(true)?;
    socket.set_recv_pktinfo(true)?;
    socket.join_multicast(std::net::Ipv6Addr::from_str("ff02::16").unwrap(), InterfaceId::UNSPECIFIED)?;
    socket.join_multicast(std::net::Ipv6Addr::from_str("ff02::2").unwrap(), InterfaceId::UNSPECIFIED)?;
    //socket.set_router_alert(0)?;
    socket.set_mrt_flag(true)?;
    let mut parser = ftthd::icmp6::Icmp6Parser::new();
    loop {
        socket.recv_parser(&mut parser)?;
        {
            let packet = parser.packet();
            let info = packet.info.as_ref().unwrap();
            let ifname = interface::index_to_name(info.if_index)?;
            let src = packet.target_addr;
            let dst = info.addr;
            let ttl = packet.hop_limit.unwrap().hop_limit;
            print!("[{}] {} -> {} (ttl: {})", ifname, src, dst, ttl);
        }

        let parsed = parser.parse();
        match parsed {
            Ok(parsed) => {
                match parsed {
                    Icmp6Packet::RouterSolicitation(rs) => {
                        print!(" {:?}", rs);
                    }

                    Icmp6Packet::RouterAdvertisement(ra) => {
                        print!(" {:?}", ra);
                    }

                    Icmp6Packet::NeighborSolicitation(ns) => {
                        print!(" {:?}", ns);
                    }

                    Icmp6Packet::NeighborAdvertisement(na) => {
                        print!(" {:?}", na);
                    }

                    Icmp6Packet::Redirect(r) => {
                        print!(" {:?}", r);
                    }

                    Icmp6Packet::MulticastListenerQuery(mlq) => {
                        print!(" {:?}", mlq);
                    }

                    Icmp6Packet::V1MulticastListenerReport(mlr) => {
                        print!(" {:?}", mlr);
                    }

                    Icmp6Packet::V1MulticastListenerDone(mld) => {
                        print!(" {:?}", mld);
                    }

                    Icmp6Packet::V2MulticastListenerReport(mlr) => {
                        print!(" {:?}", mlr);
                    }

                    _ => {
                        print!(" {:?}", parsed);
                    }
                }
            }
            Err(e) => {
                print!(" ICMPv6 <err: {}>", e);
            }
        }
        println!();
    }
}


use ftthd::interface::{InterfaceId, InterfaceStateManager};
use ftthd::group::MldSubscriptionManager;
use ftthd::group::NdpMulticastManager;

use clap::{Parser, Subcommand};

use std::collections::HashSet;
use std::net::Ipv6Addr;
use std::path::PathBuf;


fn main() {
    env_logger::init();
    let args = Cli::parse();
    let config_manager = ftthd::config::ConfigManager::new(&args.config);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        if let Err(e) = config_manager.load().await {
            log::warn!("Failed to load configuration: {:?}", e);
        }

        let config = config_manager.clone();
        tokio::spawn(async move {
            while !config_manager.is_loaded() {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let _ = config_manager.load().await;
            }

            log::info!("Configuration loaded");
        });

        // enable config reloader for daemon subcommands
        let config_reloader = config.clone();
        let enable_config_reloader = move || {
            tokio::spawn(async move {
                let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).unwrap();
                loop {
                    signal.recv().await;
                    log::info!("Received SIGHUP, reloading configuration");
                    if let Err(e) = config_reloader.load().await {
                        log::warn!("Failed to reload configuration: {:?}", e);
                    }
                }
            });
        };

        match args.subcmd {
            Command::Start => {
                enable_config_reloader();
                start(config).await;
            }

            #[allow(unreachable_patterns)]
            _ => {
                log::error!("Invalid subcommand");
            }
        }
    });
}

async fn start(config: ftthd::config::ConfigManager) {
    if !config.is_loaded() {
        log::warn!("Configuration not loaded, waiting til configured");
        config.subscribe().recv().await.unwrap();
        assert!(config.is_loaded());
    }

    {
        let config_data = config.get().unwrap();
        log::debug!("Configuration: {:?}", config_data);
    }

    tokio::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1").await.unwrap();
    tokio::fs::write("/proc/sys/net/ipv6/conf/all/proxy_ndp", "1").await.unwrap();

    let if_manager = InterfaceStateManager::new().await;

    let raw_socket = ftthd::icmp6::RawIcmp6Socket::new().unwrap();
    raw_socket.set_mrt_flag(true).unwrap();
    raw_socket.set_recv_hoplimit(true).unwrap();
    raw_socket.set_recv_hopopts(true).unwrap();
    raw_socket.set_recv_pktinfo(true).unwrap();
    raw_socket.set_multicast_loop(false).unwrap();
    raw_socket.set_multicast_all(true).unwrap();
    raw_socket.set_autoflowlabel(false).unwrap();

    raw_socket.join_multicast("ff02::16".parse().unwrap(), InterfaceId::UNSPECIFIED).unwrap();

    let socket = ftthd::icmp6::AsyncIcmp6Socket::new(raw_socket);

    let rtnl = ftthd::rtnl::RtnetlinkConnection::new().await.unwrap();
    let mut rtnl_link = rtnl.link();
    let rtnl_route = rtnl.route();
    let rtnl_neighbor = rtnl.neighbor();

    let downstream_if_ids = config.get().unwrap().interfaces.downstreams.iter().map(|name| {
        if_manager.get_index_by_name(name).unwrap()
    }).collect::<Vec<_>>();

    let upstream_if_id = if_manager.get_index_by_name(&config.get().unwrap().interfaces.upstream).unwrap();

    let upstream_global_addrs = rtnl.address().get_v6(upstream_if_id, ftthd::rtnl::addr::V6AddressRequestScope::Global).await.unwrap();

    for addr in &upstream_global_addrs {
        for if_id in downstream_if_ids.iter() {
            let _ = rtnl_neighbor.proxy_delete(*if_id, std::net::IpAddr::V6(*addr)).await;

            if let Err(e) = rtnl_neighbor.proxy_add(*if_id, std::net::IpAddr::V6(*addr)).await {
                log::error!("Failed to add proxy neighbor: {:?}", e);
            }
        }
    }

    if downstream_if_ids.contains(&upstream_if_id) {
        log::error!("Upstream interface is also a downstream interface");
        return;
    }

    let interface_ids = config.get().unwrap().interfaces.interfaces().iter().map(|name| {
        if_manager.get_index_by_name(name).unwrap()
    }).collect::<Vec<_>>();

    for if_id in interface_ids {
        let _ = rtnl_link.set_all_multicast_mode(if_id, true).await;
    }

    let mut subscription_manager = MldSubscriptionManager::new(socket.clone(), config.get().unwrap().interfaces.clone());
    let mut ndp_multicast_manager = NdpMulticastManager::new(socket.clone(), config.get().unwrap().interfaces.clone());

    let mut parser = ftthd::icmp6::Icmp6Parser::new();
    let mut writer = ftthd::icmp6::Icmp6Writer::new();
    loop {
        socket.recv_parser(&mut parser).await.unwrap();
        let packet = parser.parse();
        let packet = if let Ok(packet) = packet {
            packet
        } else {
            log::error!("Failed to parse packet: {:?}", packet);
            continue;
        };
        let raw_packet = parser.packet();
        match packet {
            ftthd::icmp6::Icmp6Packet::RouterSolicitation(mut rs) => {
                let info = raw_packet.info.unwrap();
                let in_if = info.if_index;
                let dst = info.addr;
                let if_name = if_manager.get(in_if).unwrap().if_name;

                let config = config.get().unwrap();

                if !config.interfaces.downstreams.contains(&if_name) {
                    log::debug!("Received Router Solicitation from non-downstream interface: {}", if_name);
                    continue;
                }

                let out_if = &config.interfaces.upstream;
                let out_if_index = if_manager.get_index_by_name(out_if).unwrap();

                let source = if_manager.get_link_local_addr(out_if_index);

                let source = if let Some(source) = source {
                    source
                } else {
                    log::warn!("Failed to get link-local address for upstream interface: {}", out_if);
                    continue;
                };

                rs.options = rs.options.iter().filter(|opt| {
                    if opt.option_type == 1 {
                        false
                    } else {
                        true
                    }
                }).cloned().collect();

                if let Ok(Some(link_layer_address)) = rtnl_link.get_link_layer_address(out_if_index).await {
                    rs.options.push(ftthd::icmp6::ndp::NdpOption {
                        option_type: 1,
                        option_data: link_layer_address,
                    });
                }

                let info = ftthd::icmp6::packet::PacketInfo {
                    if_index: out_if_index,
                    addr: source,
                };
                writer.set_destination(dst);
                writer.set_packet_info(Some(info));
                writer.set_hop_limit(Some(255));
                writer.set_hop_by_hop(None);
                if let Err(e) = writer.set_packet(ftthd::icmp6::Icmp6Packet::RouterSolicitation(rs.clone())) {
                    log::error!("Failed to set Router Solicitation: {:?}, rs: {:?}", e, &rs);
                    continue;
                }

                if let Err(e) = socket.send_writer(&writer).await {
                    log::error!("Failed to send Router Solicitation: {:?}", e);
                }
            }

            ftthd::icmp6::Icmp6Packet::RouterAdvertisement(mut ra) => {
                let info = raw_packet.info.unwrap();
                let in_if = info.if_index;
                let dst = info.addr;
                let if_name = if_manager.get(in_if).unwrap().if_name;

                let config = config.get().unwrap();

                if config.interfaces.upstream != if_name {
                    log::debug!("Received Router Advertisement from non-upstream interface: {}", if_name);
                    continue;
                }

                let out_ifs = config.interfaces.downstreams.iter().map(|name| {
                    if_manager.get_index_by_name(name).unwrap()
                }).collect::<Vec<_>>();

                ra.options = ra.options.iter().filter(|opt| {
                    if opt.option_type == 1 {
                        false
                    } else {
                        true
                    }
                }).cloned().collect::<Vec<_>>();

                for out_if_index in out_ifs {
                    let source = if_manager.get_link_local_addr(out_if_index);

                    let source = if let Some(source) = source {
                        source
                    } else {
                        log::warn!("Failed to get link-local address for downstream interface: {}", if_manager.get(out_if_index).unwrap().if_name);
                        continue;
                    };

                    let info = ftthd::icmp6::packet::PacketInfo {
                        if_index: out_if_index,
                        addr: source,
                    };
                    writer.set_destination(dst);
                    writer.set_packet_info(Some(info));
                    writer.set_hop_limit(Some(255));
                    writer.set_hop_by_hop(None);
                    if let Err(e) = writer.set_packet(ftthd::icmp6::Icmp6Packet::RouterAdvertisement(ra.clone())) {
                        log::error!("Failed to set Router Advertisement: {:?}, ra: {:?}", e, &ra);
                        continue;
                    }

                    if let Err(e) = socket.send_writer(&writer).await {
                        log::error!("Failed to send Router Advertisement: {:?}, writer: {:?}", e, &writer);
                    }
                }
            }

            ftthd::icmp6::Icmp6Packet::NeighborSolicitation(mut ns) => {
                let info = raw_packet.info.unwrap();
                let in_if = info.if_index;
                let dst = info.addr;
                let if_name = if_manager.get(in_if).unwrap().if_name;

                let config = config.get().unwrap();

                let ifs = config.interfaces.interfaces();
                if !ifs.contains(&if_name) {
                    log::debug!("Received Neighbor Solicitation from non-configured interface: {}", if_name);
                    continue;
                }

                let tgt_addr = ns.target_address;

                if tgt_addr.is_unicast_link_local() {
                    log::debug!("Received Neighbor Solicitation for link-local address: {}", tgt_addr);
                    continue;
                } else {
                    log::info!("Received Neighbor Solicitation for non-link-local address: {}", tgt_addr);
                }

                if upstream_global_addrs.contains(&tgt_addr) {
                    log::debug!("Received Neighbor Solicitation for upstream global address: {}", tgt_addr);
                    continue;
                }

                let out_ifs = config.interfaces.interfaces().iter().filter(|name| {
                    name != &&if_name
                }).map(|name| {
                    if_manager.get_index_by_name(name).unwrap()
                }).collect::<Vec<_>>();

                ns.options = ns.options.iter().filter(|opt| {
                    if opt.option_type == 1 {
                        false
                    } else {
                        true
                    }
                }).cloned().collect::<Vec<_>>();

                for out_if_index in out_ifs {
                    let mut ns = ns.clone();

                    if let Ok(Some(link_layer_address)) = rtnl_link.get_link_layer_address(out_if_index).await {
                        ns.options.push(ftthd::icmp6::ndp::NdpOption {
                            option_type: 1,
                            option_data: link_layer_address,
                        });
                    }

                    let source = if_manager.get_link_local_addr(out_if_index);

                    let source = if let Some(source) = source {
                        source
                    } else {
                        log::warn!("Failed to get link-local address for downstream interface: {}", if_manager.get(out_if_index).unwrap().if_name);
                        continue;
                    };

                    let info = ftthd::icmp6::packet::PacketInfo {
                        if_index: out_if_index,
                        addr: source,
                    };
                    writer.set_destination(dst);
                    writer.set_packet_info(Some(info));
                    writer.set_hop_limit(Some(255));
                    writer.set_hop_by_hop(None);
                    if let Err(e) = writer.set_packet(ftthd::icmp6::Icmp6Packet::NeighborSolicitation(ns.clone())) {
                        log::error!("Failed to set Neighbor Solicitation: {:?}, ns: {:?}", e, &ns);
                        continue;
                    }

                    if let Err(e) = socket.send_writer(&writer).await {
                        log::error!("Failed to send Neighbor Solicitation: {:?}, writer: {:?}", e, &writer);
                    }
                }
            }

            ftthd::icmp6::Icmp6Packet::NeighborAdvertisement(na) => {
                let info = raw_packet.info.unwrap();
                let in_if = info.if_index;
                let if_name = if_manager.get(in_if).unwrap().if_name;
                
                let config = config.get().unwrap();

                let ifs = config.interfaces.interfaces();
                if !ifs.contains(&if_name) {
                    log::debug!("Received Neighbor Advertisement from non-configured interface: {}", if_name);
                    continue;
                }

                let tgt_addr = na.target_address;
                if tgt_addr.is_unicast_link_local() {
                    log::debug!("Received Neighbor Advertisement for link-local address: {}", tgt_addr);
                    continue;
                } else {
                    log::info!("Received Neighbor Advertisement for non-link-local address: {}", tgt_addr);
                }

                let out_ifs = config.interfaces.interfaces().iter().filter(|name| {
                    name != &&if_name
                }).map(|name| {
                    if_manager.get_index_by_name(name).unwrap()
                }).collect::<Vec<_>>();

                let _ = rtnl_route.delete_v6(InterfaceId::UNSPECIFIED, tgt_addr, 128, None).await;

                if let Err(e) = rtnl_route.add_v6(in_if, tgt_addr, 128, None).await {
                    log::error!("Failed to add route: {:?}", e);
                }

                let _ = rtnl_neighbor.proxy_delete(in_if, std::net::IpAddr::V6(tgt_addr)).await;

                for out_if_index in out_ifs {
                    let _ = rtnl_neighbor.proxy_delete(out_if_index, std::net::IpAddr::V6(tgt_addr)).await;

                    if let Err(e) = rtnl_neighbor.proxy_add(out_if_index, std::net::IpAddr::V6(tgt_addr)).await {
                        log::error!("Failed to add proxy neighbor: {:?}", e);
                    }
                }
            }

            ftthd::icmp6::Icmp6Packet::Redirect(r) => {
                log::info!("Redirect: {:?}", r);
            }

            ftthd::icmp6::Icmp6Packet::MulticastListenerQuery(mlq) => {
                let in_if = raw_packet.info.unwrap().if_index;
                let if_name = if_manager.get(in_if).unwrap().if_name;

                let config = config.get().unwrap();

                if config.interfaces.upstream != if_name {
                    log::debug!("Received Multicast Listener Query from non-configured interface: {}", if_name);
                    continue;
                }

                let group_addr = mlq.group_address;

                if group_addr < "ff03::".parse::<Ipv6Addr>().unwrap() {
                    log::debug!("Received Multicast Listener Query for link-local or node-local group: {}", group_addr);
                    continue;
                }

                subscription_manager.remove_old_subscriptions(300);
                let groups = subscription_manager.get_groups();
                if !groups.contains(&group_addr) {
                    log::debug!("Received Multicast Listener Query for non-subscribed group: {}", group_addr);
                    continue;
                }

                let source_addresses = subscription_manager.get_source_addresses(group_addr).iter().map(|addr| *addr).collect::<Vec<_>>();
                let record_type = if !source_addresses.is_empty() {
                    1 // MODE_IS_INCLUDE
                } else {
                    2 // MODE_IS_EXCLUDE
                };

                let report_record = ftthd::icmp6::mld::MulticastReportRecord {
                    multicast_address: group_addr,
                    record_type,
                    source_addresses,
                };

                let report = ftthd::icmp6::mld::V2MulticastListenerReport {
                    records: vec![report_record],
                };

                let src = if_manager.get_link_local_addr(in_if).unwrap();

                writer.set_destination("ff02::16".parse().unwrap());
                writer.set_hop_limit(Some(1));
                writer.set_packet_info(Some(ftthd::icmp6::packet::PacketInfo {
                    if_index: in_if,
                    addr: src,
                }));

                if let Err(e) = writer.set_packet(ftthd::icmp6::Icmp6Packet::V2MulticastListenerReport(report)) {
                    log::error!("Failed to set Multicast Listener Report: {:?}", e);
                    continue;
                }

                if let Err(e) = socket.send_writer(&writer).await {
                    log::error!("Failed to send Multicast Listener Report: {:?}", e);
                }

                log::info!("Sent Multicast Listener Report for group: {}", group_addr);

                let mut mlq = mlq.clone();
                mlq.source_addresses.clear();

                writer.set_destination("ff02::16".parse().unwrap());
                writer.set_hop_limit(Some(1));

                let out_ifs = config.interfaces.downstreams.iter().map(|name| {
                    if_manager.get_index_by_name(name).unwrap()
                }).collect::<Vec<_>>();

                for out_if in out_ifs {
                    let src = if_manager.get_link_local_addr(out_if).unwrap();

                    writer.set_packet_info(Some(ftthd::icmp6::packet::PacketInfo {
                        if_index: out_if,
                        addr: src,
                    }));

                    if let Err(e) = writer.set_packet(ftthd::icmp6::Icmp6Packet::MulticastListenerQuery(mlq.clone())) {
                        log::error!("Failed to set Multicast Listener Query: {:?}", e);
                        continue;
                    }

                    if let Err(e) = socket.send_writer(&writer).await {
                        log::error!("Failed to send Multicast Listener Query: {:?}", e);
                    }
                }

                log::info!("Sent Multicast Listener Query for group: {}", group_addr);
            }

            ftthd::icmp6::Icmp6Packet::V1MulticastListenerReport(mlr) => {
                log::info!("Multicast Listener Report (v1): {:?}", mlr);
            }

            ftthd::icmp6::Icmp6Packet::V1MulticastListenerDone(mld) => {
                log::info!("Multicast Listener Done (v1): {:?}", mld);
            }

            ftthd::icmp6::Icmp6Packet::V2MulticastListenerReport(mlr) => {
                let in_if = raw_packet.info.unwrap().if_index;
                let if_name = if_manager.get(in_if).unwrap().if_name;

                let config = config.get().unwrap();

                let is_from_downstream;

                if !config.interfaces.downstreams.contains(&if_name) {
                    log::debug!("Received Multicast Listener Report from non-downstream interface: {}", if_name);
                    is_from_downstream = false;
                } else {
                    is_from_downstream = true;
                }

                subscription_manager.remove_old_subscriptions(300);

                let mut records = Vec::new();
                for record in mlr.records {
                    let group = record.multicast_address;

                    if ftthd::group::is_solicited_node_address(&group) {
                        log::info!("Received Multicast Listener Report for solicited node address: {}", group);

                        ndp_multicast_manager.add_subscription(group, in_if);
                        ndp_multicast_manager.remove_old_subscriptions(3600);
                        continue;
                    }

                    if !is_from_downstream {
                        continue;
                    }

                    if group < "ff03::".parse::<Ipv6Addr>().unwrap() {
                        log::debug!("Received Multicast Listener Report for link-local or node-local group: {}", group);
                        continue;
                    }

                    let source_addresses: HashSet<_> = record.source_addresses.iter().map(|addr| *addr).collect();
                    subscription_manager.add_subscription(in_if, group, source_addresses);

                    let source_addresses = subscription_manager.get_source_addresses(group).iter().map(|addr| *addr).collect::<Vec<_>>();
                    let record_type = if !source_addresses.is_empty() {
                        1 // MODE_IS_INCLUDE
                    } else {
                        2 // MODE_IS_EXCLUDE
                    };

                    let report_record = ftthd::icmp6::mld::MulticastReportRecord {
                        multicast_address: group,
                        record_type,
                        source_addresses,
                    };
                    records.push(report_record);
                }

                let out_if_name = &config.interfaces.upstream;
                let out_if = if_manager.get_index_by_name(out_if_name).unwrap();
                let src = if_manager.get_link_local_addr(out_if).unwrap();

                writer.set_destination("ff02::16".parse().unwrap());
                writer.set_hop_limit(Some(1));
                writer.set_packet_info(Some(ftthd::icmp6::packet::PacketInfo {
                    if_index: out_if,
                    addr: src,
                }));

                if records.is_empty() {
                    log::debug!("No groups to report");
                    continue;
                }

                let report = ftthd::icmp6::mld::V2MulticastListenerReport {
                    records: records.clone(),
                };

                if let Err(e) = writer.set_packet(ftthd::icmp6::Icmp6Packet::V2MulticastListenerReport(report)) {
                    log::error!("Failed to set Multicast Listener Report: {:?}", e);
                    continue;
                }

                if let Err(e) = socket.send_writer(&writer).await {
                    log::error!("Failed to send Multicast Listener Report: {:?}, writer: {:?}", e, &writer);
                }

                log::info!("Sent Multicast Listener Report for groups: {:?}", records.iter().map(|r| r.multicast_address).collect::<Vec<_>>());
            }

            _ => {
                log::info!("Unknown packet: {:?}", packet);
            }
        }
    }
}


/// FTTHd daemon
#[derive(Debug, Clone, Parser)]
#[clap(name = "ftthd", version, about)]
pub struct Cli {
    /// Path to the configuration file
    #[clap(short, long, default_value = "/etc/ftthd.toml")]
    pub config: PathBuf,

    #[clap(subcommand)]
    pub subcmd: Command,
}

#[derive(Debug, Clone, Subcommand)]
#[non_exhaustive]
pub enum Command {
    /// start the daemon
    Start,
}

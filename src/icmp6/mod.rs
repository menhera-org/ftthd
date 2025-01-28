
pub mod socket;
pub mod packet;
pub mod mld;
pub mod ndp;

pub use socket::RawIcmp6Socket;
pub use socket::AsyncIcmp6Socket;

use mld::*;
use ndp::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmp6Error {
    message: &'static str,
}

impl Icmp6Error {
    pub fn new(message: &'static str) -> Self {
        Self {
            message,
        }
    }
}

impl std::fmt::Display for Icmp6Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for Icmp6Error {}

pub struct Icmp6Parser {
    pub(crate) packet: packet::Packet,
}

impl Icmp6Parser {
    pub fn new() -> Self {
        Self {
            packet: packet::Packet::new(),
        }
    }

    pub fn new_from_packet(packet: packet::Packet) -> Self {
        Self {
            packet,
        }
    }

    pub fn packet(&self) -> &packet::Packet {
        &self.packet
    }

    fn parse_ndp_options(&self, buf: &[u8]) -> Vec<NdpOption> {
        let mut options = Vec::new();
        let mut i = 0;
        while i + 8 < buf.len() {
            let option_type = buf[i];
            let option_length = buf[i + 1];
            let total_length = option_length as usize * 8;
            if i + total_length > buf.len() {
                break;
            }
            let option_data = buf[(i + 2)..(i + total_length)].to_vec();
            options.push(NdpOption {
                option_type,
                option_data,
            });
            i += total_length;
        }
        options
    }

    /// TODO: index validation
    pub fn parse(&self) -> Result<Icmp6Packet, Icmp6Error> {
        let packet = &self.packet;
        let ttl = packet.hop_limit.map(|hop_limit| hop_limit.hop_limit).unwrap_or(255);

        let mut router_alert_mld = false;
        if let Some(hop_by_hop) = &packet.hop_by_hop {
            let data = &hop_by_hop.hop_by_hop;
            if data.len() < 2 {
                return Err(Icmp6Error::new("HBH: <bad length>"));
            } else {
                let _next_hdr = data[0];
                let data = &data[2..];

                let mut i = 0;
                while i < data.len() {
                    let hdr = data[i];
                    if hdr == 0 {
                        break;
                    }
                    let len = data[i + 1];
                    let data = &data[(i + 2)..(i + 2 + len as usize)];
                    match hdr {
                        0x05 => {
                            let value = u16::from_be_bytes([data[0], data[1]]);
                            if value == 0 {
                                router_alert_mld = true;
                            }
                        }
                        0x01 => {}
                        _ => {}
                    }
                    i += 2 + len as usize;
                }
            }
        }

        let data = packet.data();
        if data.len() < 4 {
            return Err(Icmp6Error::new("ICMPv6 packet too short"));
        }
        let icmp6_type = data[0];
        let icmp6_code = data[1];

        match icmp6_type {
            1 => {
                Ok(Icmp6Packet::DestinationUnreachable(icmp6_code))
            }

            2 => {
                let mtu = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                Ok(Icmp6Packet::PacketTooBig(mtu))
            }

            3 => {
                Ok(Icmp6Packet::TimeExceeded(icmp6_code))
            }

            4 => {
                Ok(Icmp6Packet::ParameterProblem(icmp6_code))
            }

            128 => {
                if data.len() < 8 {
                    return Err(Icmp6Error::new("ICMPv6 packet too short"));
                }
                let identifier = u16::from_be_bytes([data[4], data[5]]);
                let sequence = u16::from_be_bytes([data[6], data[7]]);
                let data = data[8..].to_vec();
                Ok(Icmp6Packet::EchoRequest { identifier, sequence, data })
            }

            129 => {
                if data.len() < 8 {
                    return Err(Icmp6Error::new("ICMPv6 packet too short"));
                }
                let identifier = u16::from_be_bytes([data[4], data[5]]);
                let sequence = u16::from_be_bytes([data[6], data[7]]);
                let data = data[8..].to_vec();
                Ok(Icmp6Packet::EchoReply { identifier, sequence, data })
            }

            130 => {
                // multicast listener query
                if ttl != 1 {
                    return Err(Icmp6Error::new("MLD packet TTL != 1"));
                }
                if !router_alert_mld {
                    return Err(Icmp6Error::new("MLD packet with router alert"));
                }
                if data.len() < 24 {
                    return Err(Icmp6Error::new("MLD packet too short"));
                }
                let maximum_response_delay = u16::from_be_bytes([data[4], data[5]]);
                let group_address = std::net::Ipv6Addr::new(
                    u16::from_be_bytes([data[8], data[9]]),
                    u16::from_be_bytes([data[10], data[11]]),
                    u16::from_be_bytes([data[12], data[13]]),
                    u16::from_be_bytes([data[14], data[15]]),
                    u16::from_be_bytes([data[16], data[17]]),
                    u16::from_be_bytes([data[18], data[19]]),
                    u16::from_be_bytes([data[20], data[21]]),
                    u16::from_be_bytes([data[22], data[23]]),
                );
                let mut source_addresses = Vec::new();
                if data.len() < 28 {
                    Ok(Icmp6Packet::MulticastListenerQuery(MulticastListenerQuery {
                        maximum_response_delay,
                        group_address,
                        supress_router_processing: false,
                        qrv: 0,
                        qqic: 0,
                        source_addresses: Vec::new(),
                    }))
                } else {
                    let supress_router_processing = data[24] & 0x80 != 0;
                    let qrv = data[24] & 0x07;
                    let qqic = data[25];
                    let mut i = 28;
                    while i + 15 < data.len() {
                        let source_address = std::net::Ipv6Addr::new(
                            u16::from_be_bytes([data[i], data[i + 1]]),
                            u16::from_be_bytes([data[i + 2], data[i + 3]]),
                            u16::from_be_bytes([data[i + 4], data[i + 5]]),
                            u16::from_be_bytes([data[i + 6], data[i + 7]]),
                            u16::from_be_bytes([data[i + 8], data[i + 9]]),
                            u16::from_be_bytes([data[i + 10], data[i + 11]]),
                            u16::from_be_bytes([data[i + 12], data[i + 13]]),
                            u16::from_be_bytes([data[i + 14], data[i + 15]]),
                        );
                        source_addresses.push(source_address);
                        i += 16;
                    }

                    Ok(Icmp6Packet::MulticastListenerQuery(MulticastListenerQuery {
                        maximum_response_delay,
                        group_address,
                        supress_router_processing,
                        qrv,
                        qqic,
                        source_addresses,
                    }))
                }
            }

            131 => {
                // v1 multicast listener report
                if ttl != 1 {
                    return Err(Icmp6Error::new("MLD packet TTL != 1"));
                }
                if !router_alert_mld {
                    return Err(Icmp6Error::new("MLD packet with router alert"));
                }
                if data.len() < 24 {
                    return Err(Icmp6Error::new("MLD packet too short"));
                }
                let group_address = std::net::Ipv6Addr::new(
                    u16::from_be_bytes([data[8], data[9]]),
                    u16::from_be_bytes([data[10], data[11]]),
                    u16::from_be_bytes([data[12], data[13]]),
                    u16::from_be_bytes([data[14], data[15]]),
                    u16::from_be_bytes([data[16], data[17]]),
                    u16::from_be_bytes([data[18], data[19]]),
                    u16::from_be_bytes([data[20], data[21]]),
                    u16::from_be_bytes([data[22], data[23]]),
                );
                Ok(Icmp6Packet::V1MulticastListenerReport(V1MulticastListenerReport {
                    group_address,
                }))
            }

            132 => {
                // v1 multicast listener done
                if ttl != 1 {
                    return Err(Icmp6Error::new("MLD packet TTL != 1"));
                }
                if !router_alert_mld {
                    return Err(Icmp6Error::new("MLD packet with router alert"));
                }
                if data.len() < 24 {
                    return Err(Icmp6Error::new("MLD packet too short"));
                }
                let group_address = std::net::Ipv6Addr::new(
                    u16::from_be_bytes([data[8], data[9]]),
                    u16::from_be_bytes([data[10], data[11]]),
                    u16::from_be_bytes([data[12], data[13]]),
                    u16::from_be_bytes([data[14], data[15]]),
                    u16::from_be_bytes([data[16], data[17]]),
                    u16::from_be_bytes([data[18], data[19]]),
                    u16::from_be_bytes([data[20], data[21]]),
                    u16::from_be_bytes([data[22], data[23]]),
                );
                Ok(Icmp6Packet::V1MulticastListenerDone(V1MulticastListenerDone{
                    group_address,
                }))
            }

            133 => {
                // router solicitation
                if data.len() < 8 {
                    return Err(Icmp6Error::new("NDP packet too short"));
                }
                let options = self.parse_ndp_options(&data[8..]);
                Ok(Icmp6Packet::RouterSolicitation(RouterSolicitation {
                    options,
                }))
            }

            134 => {
                // router advertisement
                if data.len() < 16 {
                    return Err(Icmp6Error::new("NDP packet too short"));
                }
                let hop_limit = data[4];
                let managed_address_configuration = data[5] & 0x80 != 0;
                let other_configuration = data[5] & 0x40 != 0;
                let router_lifetime = u16::from_be_bytes([data[6], data[7]]);
                let reachable_time = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
                let retrans_timer = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
                let options = self.parse_ndp_options(&data[16..]);
                Ok(Icmp6Packet::RouterAdvertisement(RouterAdvertisement {
                    hop_limit,
                    managed_address_configuration,
                    other_configuration,
                    router_lifetime,
                    reachable_time,
                    retrans_timer,
                    options,
                }))
            }

            135 => {
                // neighbor solicitation
                if data.len() < 24 {
                    return Err(Icmp6Error::new("NDP packet too short"));
                }
                let target_address = std::net::Ipv6Addr::new(
                    u16::from_be_bytes([data[8], data[9]]),
                    u16::from_be_bytes([data[10], data[11]]),
                    u16::from_be_bytes([data[12], data[13]]),
                    u16::from_be_bytes([data[14], data[15]]),
                    u16::from_be_bytes([data[16], data[17]]),
                    u16::from_be_bytes([data[18], data[19]]),
                    u16::from_be_bytes([data[20], data[21]]),
                    u16::from_be_bytes([data[22], data[23]]),
                );
                let options = self.parse_ndp_options(&data[24..]);
                Ok(Icmp6Packet::NeighborSolicitation(NeighborSolicitation {
                    target_address,
                    options,
                }))
            }

            136 => {
                // neighbor advertisement
                if data.len() < 24 {
                    return Err(Icmp6Error::new("NDP packet too short"));
                }

                let flags = data[4];
                let router = flags & 0x80 != 0;
                let solicited = flags & 0x40 != 0;
                let override_ = flags & 0x20 != 0;

                let target_address = std::net::Ipv6Addr::new(
                    u16::from_be_bytes([data[8], data[9]]),
                    u16::from_be_bytes([data[10], data[11]]),
                    u16::from_be_bytes([data[12], data[13]]),
                    u16::from_be_bytes([data[14], data[15]]),
                    u16::from_be_bytes([data[16], data[17]]),
                    u16::from_be_bytes([data[18], data[19]]),
                    u16::from_be_bytes([data[20], data[21]]),
                    u16::from_be_bytes([data[22], data[23]]),
                );

                let options = self.parse_ndp_options(&data[24..]);
                Ok(Icmp6Packet::NeighborAdvertisement(NeighborAdvertisement {
                    router,
                    solicited,
                    override_,
                    target_address,
                    options,
                }))
            }

            137 => {
                // redirect
                if data.len() < 40 {
                    return Err(Icmp6Error::new("NDP packet too short"));
                }

                let target_address = std::net::Ipv6Addr::new(
                    u16::from_be_bytes([data[8], data[9]]),
                    u16::from_be_bytes([data[10], data[11]]),
                    u16::from_be_bytes([data[12], data[13]]),
                    u16::from_be_bytes([data[14], data[15]]),
                    u16::from_be_bytes([data[16], data[17]]),
                    u16::from_be_bytes([data[18], data[19]]),
                    u16::from_be_bytes([data[20], data[21]]),
                    u16::from_be_bytes([data[22], data[23]]),
                );

                let destination_address = std::net::Ipv6Addr::new(
                    u16::from_be_bytes([data[24], data[25]]),
                    u16::from_be_bytes([data[26], data[27]]),
                    u16::from_be_bytes([data[28], data[29]]),
                    u16::from_be_bytes([data[30], data[31]]),
                    u16::from_be_bytes([data[32], data[33]]),
                    u16::from_be_bytes([data[34], data[35]]),
                    u16::from_be_bytes([data[36], data[37]]),
                    u16::from_be_bytes([data[38], data[39]]),
                );

                let options = self.parse_ndp_options(&data[40..]);
                Ok(Icmp6Packet::Redirect(Redirect {
                    target_address,
                    destination_address,
                    options,
                }))
            }

            138 => {
                Ok(Icmp6Packet::RouterRenumbering(icmp6_code))
            }

            139 => {
                Ok(Icmp6Packet::NodeInformationQuery)
            }

            140 => {
                Ok(Icmp6Packet::NodeInformationResponse)
            }

            141 => {
                Ok(Icmp6Packet::InverseNeighborDiscoverySolicitation)
            }

            142 => {
                Ok(Icmp6Packet::InverseNeighborDiscoveryAdvertisement)
            }

            143 => {
                // v2 multicast listener report
                if ttl != 1 {
                    return Err(Icmp6Error::new("MLD packet TTL != 1"));
                }
                if !router_alert_mld {
                    return Err(Icmp6Error::new("MLD packet with router alert"));
                }
                if data.len() < 8 {
                    return Err(Icmp6Error::new("MLDv2 packet too short"));
                }

                let numrecords = u16::from_be_bytes([data[6], data[7]]);
                let mut records = Vec::new();

                let mut offset = 8;
                for _ in 0..numrecords {
                    if offset + 20 > data.len() {
                        return Err(Icmp6Error::new("MLDv2 packet too short"));
                    }

                    let record_type = data[offset];
                    let aux_data_len = data[offset + 1];
                    let numsources = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);

                    let end_offset = offset + 4 + 16 + 16 * numsources as usize + aux_data_len as usize;
                    if end_offset > data.len() {
                        return Err(Icmp6Error::new("MLDv2 packet too short"));
                    }
                    let multicast_address = std::net::Ipv6Addr::new(
                        u16::from_be_bytes([data[offset + 4], data[offset + 5]]),
                        u16::from_be_bytes([data[offset + 6], data[offset + 7]]),
                        u16::from_be_bytes([data[offset + 8], data[offset + 9]]),
                        u16::from_be_bytes([data[offset + 10], data[offset + 11]]),
                        u16::from_be_bytes([data[offset + 12], data[offset + 13]]),
                        u16::from_be_bytes([data[offset + 14], data[offset + 15]]),
                        u16::from_be_bytes([data[offset + 16], data[offset + 17]]),
                        u16::from_be_bytes([data[offset + 18], data[offset + 19]]),
                    );

                    let mut source_addresses = Vec::new();

                    for j in 0..numsources {
                        let source_address = std::net::Ipv6Addr::new(
                            u16::from_be_bytes([data[offset + 4 + 16 + 16 * j as usize + 0], data[offset + 4 + 16 + 16 * j as usize + 1]]),
                            u16::from_be_bytes([data[offset + 4 + 16 + 16 * j as usize + 2], data[offset + 4 + 16 + 16 * j as usize + 3]]),
                            u16::from_be_bytes([data[offset + 4 + 16 + 16 * j as usize + 4], data[offset + 4 + 16 + 16 * j as usize + 5]]),
                            u16::from_be_bytes([data[offset + 4 + 16 + 16 * j as usize + 6], data[offset + 4 + 16 + 16 * j as usize + 7]]),
                            u16::from_be_bytes([data[offset + 4 + 16 + 16 * j as usize + 8], data[offset + 4 + 16 + 16 * j as usize + 9]]),
                            u16::from_be_bytes([data[offset + 4 + 16 + 16 * j as usize + 10], data[offset + 4 + 16 + 16 * j as usize + 11]]),
                            u16::from_be_bytes([data[offset + 4 + 16 + 16 * j as usize + 12], data[offset + 4 + 16 + 16 * j as usize + 13]]),
                            u16::from_be_bytes([data[offset + 4 + 16 + 16 * j as usize + 14], data[offset + 4 + 16 + 16 * j as usize + 15]]),
                        );
                        source_addresses.push(source_address);
                    }

                    records.push(MulticastReportRecord {
                        record_type,
                        multicast_address,
                        source_addresses,
                    });

                    offset = end_offset;
                }
                Ok(Icmp6Packet::V2MulticastListenerReport(V2MulticastListenerReport {
                    records,
                }))
            }

            144 => {
                Ok(Icmp6Packet::HomeAgentAddressDiscoveryRequest)
            }

            145 => {
                Ok(Icmp6Packet::HomeAgentAddressDiscoveryReply)
            }

            146 => {
                Ok(Icmp6Packet::MobilePrefixSolicitation)
            }

            147 => {
                Ok(Icmp6Packet::MobilePrefixAdvertisement)
            }

            157 => {
                Ok(Icmp6Packet::DuplicateAddressRequest(icmp6_code))
            }

            158 => {
                Ok(Icmp6Packet::DuplicateAddressConfirmation(icmp6_code))
            }

            160 => {
                Ok(Icmp6Packet::ExtendedEchoRequest(icmp6_code))
            }

            161 => {
                Ok(Icmp6Packet::ExtendedEchoReply(icmp6_code))
            }

            _ => {
                Ok(Icmp6Packet::Unknown(icmp6_type, icmp6_code))
            }
        }
    }
}


#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Icmp6Packet {
    /// type 1
    /// code
    DestinationUnreachable(u8),

    /// type 2
    /// MTU
    PacketTooBig(u32),

    /// type 3
    /// code
    TimeExceeded(u8),

    /// type 4
    /// code
    ParameterProblem(u8),

    /// type 128
    EchoRequest { identifier: u16, sequence: u16, data: Vec<u8> },

    /// type 129
    EchoReply { identifier: u16, sequence: u16, data: Vec<u8> },

    /// type 130
    MulticastListenerQuery(MulticastListenerQuery),

    /// type 131
    V1MulticastListenerReport(V1MulticastListenerReport),

    /// type 132
    V1MulticastListenerDone(V1MulticastListenerDone),

    /// type 133
    RouterSolicitation(RouterSolicitation),

    /// type 134
    RouterAdvertisement(RouterAdvertisement),

    /// type 135
    NeighborSolicitation(NeighborSolicitation),

    /// type 136
    NeighborAdvertisement(NeighborAdvertisement),

    /// type 137
    Redirect(Redirect),

    /// type 138
    /// code
    RouterRenumbering(u8),

    /// type 139
    NodeInformationQuery,

    /// type 140
    NodeInformationResponse,

    /// type 141
    InverseNeighborDiscoverySolicitation,

    /// type 142
    InverseNeighborDiscoveryAdvertisement,

    /// type 143
    V2MulticastListenerReport(V2MulticastListenerReport),

    /// type 144
    HomeAgentAddressDiscoveryRequest,

    /// type 145
    HomeAgentAddressDiscoveryReply,

    /// type 146
    MobilePrefixSolicitation,

    /// type 147
    MobilePrefixAdvertisement,

    /// type 157
    /// code
    DuplicateAddressRequest(u8),

    /// type 158
    /// code
    DuplicateAddressConfirmation(u8),

    /// type 160
    /// code
    ExtendedEchoRequest(u8),

    /// type 161
    /// code
    ExtendedEchoReply(u8),

    /// type, code
    Unknown(u8, u8),
}

#[derive(Debug)]
pub struct Icmp6Writer {
    pub(crate) packet: packet::Packet,
}

impl Icmp6Writer {
    pub fn new() -> Self {
        Self {
            packet: packet::Packet::new(),
        }
    }

    pub fn set_destination(&mut self, addr: std::net::Ipv6Addr) {
        self.packet.target_addr = addr;
    }

    pub fn set_hop_limit(&mut self, hop_limit: Option<u8>) {
        self.packet.hop_limit = hop_limit.map(|hop_limit| packet::PacketHopLimit { hop_limit });
    }

    pub fn set_hop_by_hop(&mut self, hop_by_hop: Option<Vec<u8>>) {
        self.packet.hop_by_hop = hop_by_hop.map(|hop_by_hop| packet::PacketHopByHop { hop_by_hop });
    }

    pub fn set_packet_info(&mut self, info: Option<packet::PacketInfo>) {
        self.packet.info = info;
    }

    pub fn setup_mld(&mut self) {
        self.set_hop_limit(Some(1));
        let mut hop_by_hop = vec![0u8; 8];

        // next header (MLD)
        hop_by_hop[0] = 0x3a;

        // length
        hop_by_hop[1] = 0x00;

        // padding
        hop_by_hop[2] = 0x01;
        hop_by_hop[3] = 0x00;

        // router alert
        hop_by_hop[4] = 0x05;
        hop_by_hop[5] = 0x02;
        hop_by_hop[6] = 0x00;
        hop_by_hop[7] = 0x00;

        self.set_hop_by_hop(Some(hop_by_hop));
    }

    fn serialize_ndp_options(&self, options: &[NdpOption]) -> Vec<u8> {
        let mut data = Vec::new();
        for option in options {
            let orig_len = option.option_data.len();

            if orig_len > 1500 {
                continue;
            }
            let rem = (2 + orig_len) % 8;
            let option_data = if rem == 0 {
                option.option_data.clone()
            } else {
                let mut option_data = Vec::new();
                option_data.extend_from_slice(&option.option_data);
                option_data.resize(orig_len + 8 - rem, 0);
                option_data
            };

            let option_length = ((option_data.len() + 2) / 8) as u8;
            data.push(option.option_type);
            data.push(option_length);
            data.extend_from_slice(&option_data);
            if data.len() > 1500 {
                break;
            }
        }
        data
    }

    pub fn set_packet(&mut self, packet: Icmp6Packet) -> Result<(), Icmp6Error> {
        // let mut data: Vec<u8> = Vec::new();
        match packet {
            Icmp6Packet::EchoRequest { identifier, sequence, data: payload } => {
                let mut data = vec![0u8; 8 + payload.len()];
                data[0] = 128;
                data[1] = 0;
                data[2] = 0;
                data[3] = 0;
                data[4] = (identifier >> 8) as u8;
                data[5] = (identifier & 255) as u8;
                data[6] = (sequence >> 8) as u8;
                data[7] = (sequence & 255) as u8;
                data[8..].copy_from_slice(&payload);
                self.packet.data_len = data.len();
                self.packet.data[..data.len()].copy_from_slice(&data);

                Ok(())
            }

            Icmp6Packet::EchoReply { identifier, sequence, data: payload } => {
                let mut data = vec![0u8; 8 + payload.len()];
                data[0] = 129;
                data[1] = 0;
                data[2] = 0;
                data[3] = 0;
                data[4] = (identifier >> 8) as u8;
                data[5] = (identifier & 255) as u8;
                data[6] = (sequence >> 8) as u8;
                data[7] = (sequence & 255) as u8;
                data[8..].copy_from_slice(&payload);
                self.packet.data_len = data.len();
                self.packet.data[..data.len()].copy_from_slice(&data);

                Ok(())
            }

            Icmp6Packet::MulticastListenerQuery(query) => {
                let mut data = vec![0u8; 28];
                data[0] = 130;
                data[1] = 0;
                data[2] = 0;
                data[3] = 0;
                data[4] = (query.maximum_response_delay >> 8) as u8;
                data[5] = (query.maximum_response_delay & 255) as u8;
                data[6] = 0;
                data[7] = 0;

                let group_segments = query.group_address.segments();
                data[8] = (group_segments[0] >> 8) as u8;
                data[9] = (group_segments[0] & 255) as u8;
                data[10] = (group_segments[1] >> 8) as u8;
                data[11] = (group_segments[1] & 255) as u8;
                data[12] = (group_segments[2] >> 8) as u8;
                data[13] = (group_segments[2] & 255) as u8;
                data[14] = (group_segments[3] >> 8) as u8;
                data[15] = (group_segments[3] & 255) as u8;
                data[16] = (group_segments[4] >> 8) as u8;
                data[17] = (group_segments[4] & 255) as u8;
                data[18] = (group_segments[5] >> 8) as u8;
                data[19] = (group_segments[5] & 255) as u8;
                data[20] = (group_segments[6] >> 8) as u8;
                data[21] = (group_segments[6] & 255) as u8;
                data[22] = (group_segments[7] >> 8) as u8;
                data[23] = (group_segments[7] & 255) as u8;

                data[24] = if query.supress_router_processing { 0x80 } else { 0x00 };
                data[24] |= query.qrv & 0x07;
                data[25] = query.qqic;

                if query.source_addresses.len() > 80 {
                    return Err(Icmp6Error::new("MLD query source addresses too many"));
                }

                data.resize(28 + query.source_addresses.len() * 16, 0);

                data[26] = (query.source_addresses.len() >> 8) as u8;
                data[27] = (query.source_addresses.len() & 255) as u8;

                for (i, source_address) in query.source_addresses.iter().enumerate() {
                    let source_segments = source_address.segments();
                    data[28 + i * 16] = (source_segments[0] >> 8) as u8;
                    data[29 + i * 16] = (source_segments[0] & 255) as u8;
                    data[30 + i * 16] = (source_segments[1] >> 8) as u8;
                    data[31 + i * 16] = (source_segments[1] & 255) as u8;
                    data[32 + i * 16] = (source_segments[2] >> 8) as u8;
                    data[33 + i * 16] = (source_segments[2] & 255) as u8;
                    data[34 + i * 16] = (source_segments[3] >> 8) as u8;
                    data[35 + i * 16] = (source_segments[3] & 255) as u8;
                    data[36 + i * 16] = (source_segments[4] >> 8) as u8;
                    data[37 + i * 16] = (source_segments[4] & 255) as u8;
                    data[38 + i * 16] = (source_segments[5] >> 8) as u8;
                    data[39 + i * 16] = (source_segments[5] & 255) as u8;
                    data[40 + i * 16] = (source_segments[6] >> 8) as u8;
                    data[41 + i * 16] = (source_segments[6] & 255) as u8;
                    data[42 + i * 16] = (source_segments[7] >> 8) as u8;
                    data[43 + i * 16] = (source_segments[7] & 255) as u8;
                }

                self.packet.data_len = data.len();
                self.packet.data[..data.len()].copy_from_slice(&data);

                self.setup_mld();
                Ok(())
            }

            Icmp6Packet::V2MulticastListenerReport(report) => {
                let mut data = vec![0u8; 8];
                data[0] = 143;

                let count = report.records.len() as u16;
                data[6] = (count >> 8) as u8;
                data[7] = (count & 255) as u8;

                for record in report.records {
                    let sources_count = record.source_addresses.len() as u16;
                    if sources_count > 80 {
                        return Err(Icmp6Error::new("MLDv2 report source addresses too many"));
                    }

                    let mut record_data = vec![0u8; 20 + 16 * sources_count as usize];
                    record_data[0] = record.record_type;
                    record_data[1] = 0;
                    record_data[2] = (sources_count >> 8) as u8;
                    record_data[3] = (sources_count & 255) as u8;

                    let multicast_segments = record.multicast_address.segments();
                    record_data[4] = (multicast_segments[0] >> 8) as u8;
                    record_data[5] = (multicast_segments[0] & 255) as u8;
                    record_data[6] = (multicast_segments[1] >> 8) as u8;
                    record_data[7] = (multicast_segments[1] & 255) as u8;
                    record_data[8] = (multicast_segments[2] >> 8) as u8;
                    record_data[9] = (multicast_segments[2] & 255) as u8;
                    record_data[10] = (multicast_segments[3] >> 8) as u8;
                    record_data[11] = (multicast_segments[3] & 255) as u8;
                    record_data[12] = (multicast_segments[4] >> 8) as u8;
                    record_data[13] = (multicast_segments[4] & 255) as u8;
                    record_data[14] = (multicast_segments[5] >> 8) as u8;
                    record_data[15] = (multicast_segments[5] & 255) as u8;
                    record_data[16] = (multicast_segments[6] >> 8) as u8;
                    record_data[17] = (multicast_segments[6] & 255) as u8;
                    record_data[18] = (multicast_segments[7] >> 8) as u8;
                    record_data[19] = (multicast_segments[7] & 255) as u8;

                    for (i, source_address) in record.source_addresses.iter().enumerate() {
                        let source_segments = source_address.segments();
                        record_data[20 + i * 16] = (source_segments[0] >> 8) as u8;
                        record_data[21 + i * 16] = (source_segments[0] & 255) as u8;
                        record_data[22 + i * 16] = (source_segments[1] >> 8) as u8;
                        record_data[23 + i * 16] = (source_segments[1] & 255) as u8;
                        record_data[24 + i * 16] = (source_segments[2] >> 8) as u8;
                        record_data[25 + i * 16] = (source_segments[2] & 255) as u8;
                        record_data[26 + i * 16] = (source_segments[3] >> 8) as u8;
                        record_data[27 + i * 16] = (source_segments[3] & 255) as u8;
                        record_data[28 + i * 16] = (source_segments[4] >> 8) as u8;
                        record_data[29 + i * 16] = (source_segments[4] & 255) as u8;
                        record_data[30 + i * 16] = (source_segments[5] >> 8) as u8;
                        record_data[31 + i * 16] = (source_segments[5] & 255) as u8;
                        record_data[32 + i * 16] = (source_segments[6] >> 8) as u8;
                        record_data[33 + i * 16] = (source_segments[6] & 255) as u8;
                        record_data[34 + i * 16] = (source_segments[7] >> 8) as u8;
                        record_data[35 + i * 16] = (source_segments[7] & 255) as u8;
                    }

                    data.extend_from_slice(&record_data);
                    if data.len() > 1500 {
                        return Err(Icmp6Error::new("MLDv2 packet too long"));
                    }
                }

                self.packet.data_len = data.len();
                self.packet.data[..data.len()].copy_from_slice(&data);

                self.setup_mld();
                Ok(())
            }

            Icmp6Packet::RouterSolicitation(solicitation) => {
                let mut data = vec![0u8; 8];
                data[0] = 133;
                data[1] = 0;
                data[2] = 0;
                data[3] = 0;

                let options = self.serialize_ndp_options(&solicitation.options);
                data.extend_from_slice(&options);

                self.packet.data_len = data.len();
                self.packet.data[..data.len()].copy_from_slice(&data);

                Ok(())
            }

            Icmp6Packet::RouterAdvertisement(advertisement) => {
                let mut data = vec![0u8; 16];
                data[0] = 134;
                data[1] = 0;
                data[2] = 0;
                data[3] = 0;
                data[4] = advertisement.hop_limit;
                data[5] = if advertisement.managed_address_configuration { 0x80 } else { 0x00 };
                data[5] |= if advertisement.other_configuration { 0x40 } else { 0x00 };
                data[6] = (advertisement.router_lifetime >> 8) as u8;
                data[7] = (advertisement.router_lifetime & 255) as u8;
                data[8] = (advertisement.reachable_time >> 24) as u8;
                data[9] = (advertisement.reachable_time >> 16) as u8;
                data[10] = (advertisement.reachable_time >> 8) as u8;
                data[11] = (advertisement.reachable_time & 255) as u8;
                data[12] = (advertisement.retrans_timer >> 24) as u8;
                data[13] = (advertisement.retrans_timer >> 16) as u8;
                data[14] = (advertisement.retrans_timer >> 8) as u8;
                data[15] = (advertisement.retrans_timer & 255) as u8;

                let options = self.serialize_ndp_options(&advertisement.options);
                data.extend_from_slice(&options);

                self.packet.data_len = data.len();
                self.packet.data[..data.len()].copy_from_slice(&data);

                Ok(())
            }

            Icmp6Packet::NeighborSolicitation(solicitation) => {
                let mut data = vec![0u8; 24];
                data[0] = 135;
                data[1] = 0;
                data[2] = 0;
                data[3] = 0;

                let target_segments = solicitation.target_address.segments();
                data[8] = (target_segments[0] >> 8) as u8;
                data[9] = (target_segments[0] & 255) as u8;
                data[10] = (target_segments[1] >> 8) as u8;
                data[11] = (target_segments[1] & 255) as u8;
                data[12] = (target_segments[2] >> 8) as u8;
                data[13] = (target_segments[2] & 255) as u8;
                data[14] = (target_segments[3] >> 8) as u8;
                data[15] = (target_segments[3] & 255) as u8;
                data[16] = (target_segments[4] >> 8) as u8;
                data[17] = (target_segments[4] & 255) as u8;
                data[18] = (target_segments[5] >> 8) as u8;
                data[19] = (target_segments[5] & 255) as u8;
                data[20] = (target_segments[6] >> 8) as u8;
                data[21] = (target_segments[6] & 255) as u8;
                data[22] = (target_segments[7] >> 8) as u8;
                data[23] = (target_segments[7] & 255) as u8;

                let options = self.serialize_ndp_options(&solicitation.options);
                data.extend_from_slice(&options);

                self.packet.data_len = data.len();
                self.packet.data[..data.len()].copy_from_slice(&data);

                Ok(())
            }

            Icmp6Packet::NeighborAdvertisement(advertisement) => {
                let mut data = vec![0u8; 24];
                data[0] = 136;
                data[1] = 0;
                data[2] = 0;
                data[3] = 0;

                let target_segments = advertisement.target_address.segments();
                data[8] = (target_segments[0] >> 8) as u8;
                data[9] = (target_segments[0] & 255) as u8;
                data[10] = (target_segments[1] >> 8) as u8;
                data[11] = (target_segments[1] & 255) as u8;
                data[12] = (target_segments[2] >> 8) as u8;
                data[13] = (target_segments[2] & 255) as u8;
                data[14] = (target_segments[3] >> 8) as u8;
                data[15] = (target_segments[3] & 255) as u8;
                data[16] = (target_segments[4] >> 8) as u8;
                data[17] = (target_segments[4] & 255) as u8;
                data[18] = (target_segments[5] >> 8) as u8;
                data[19] = (target_segments[5] & 255) as u8;
                data[20] = (target_segments[6] >> 8) as u8;
                data[21] = (target_segments[6] & 255) as u8;
                data[22] = (target_segments[7] >> 8) as u8;
                data[23] = (target_segments[7] & 255) as u8;

                data[4] = if advertisement.router { 0x80 } else { 0x00 };
                data[4] |= if advertisement.solicited { 0x40 } else { 0x00 };
                data[4] |= if advertisement.override_ { 0x20 } else { 0x00 };

                let options = self.serialize_ndp_options(&advertisement.options);
                data.extend_from_slice(&options);

                self.packet.data_len = data.len();
                self.packet.data[..data.len()].copy_from_slice(&data);

                Ok(())
            }

            Icmp6Packet::Redirect(redirect) => {
                let mut data = vec![0u8; 40];
                data[0] = 137;
                data[1] = 0;
                data[2] = 0;
                data[3] = 0;

                let target_segments = redirect.target_address.segments();
                data[8] = (target_segments[0] >> 8) as u8;
                data[9] = (target_segments[0] & 255) as u8;
                data[10] = (target_segments[1] >> 8) as u8;
                data[11] = (target_segments[1] & 255) as u8;
                data[12] = (target_segments[2] >> 8) as u8;
                data[13] = (target_segments[2] & 255) as u8;
                data[14] = (target_segments[3] >> 8) as u8;
                data[15] = (target_segments[3] & 255) as u8;
                data[16] = (target_segments[4] >> 8) as u8;
                data[17] = (target_segments[4] & 255) as u8;
                data[18] = (target_segments[5] >> 8) as u8;
                data[19] = (target_segments[5] & 255) as u8;
                data[20] = (target_segments[6] >> 8) as u8;
                data[21] = (target_segments[6] & 255) as u8;
                data[22] = (target_segments[7] >> 8) as u8;
                data[23] = (target_segments[7] & 255) as u8;

                let destination_segments = redirect.destination_address.segments();
                data[24] = (destination_segments[0] >> 8) as u8;
                data[25] = (destination_segments[0] & 255) as u8;
                data[26] = (destination_segments[1] >> 8) as u8;
                data[27] = (destination_segments[1] & 255) as u8;
                data[28] = (destination_segments[2] >> 8) as u8;
                data[29] = (destination_segments[2] & 255) as u8;
                data[30] = (destination_segments[3] >> 8) as u8;
                data[31] = (destination_segments[3] & 255) as u8;
                data[32] = (destination_segments[4] >> 8) as u8;
                data[33] = (destination_segments[4] & 255) as u8;
                data[34] = (destination_segments[5] >> 8) as u8;
                data[35] = (destination_segments[5] & 255) as u8;
                data[36] = (destination_segments[6] >> 8) as u8;
                data[37] = (destination_segments[6] & 255) as u8;
                data[38] = (destination_segments[7] >> 8) as u8;
                data[39] = (destination_segments[7] & 255) as u8;

                let options = self.serialize_ndp_options(&redirect.options);
                data.extend_from_slice(&options);

                self.packet.data_len = data.len();
                self.packet.data[..data.len()].copy_from_slice(&data);

                Ok(())
            }

            _ => {
                return Err(Icmp6Error::new("ICMPv6 packet type is not supported"));
            }
        }
    }
}
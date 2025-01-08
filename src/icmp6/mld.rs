

#[derive(Debug, Clone)]
pub struct MulticastReportRecord {
    pub record_type: u8,
    //pub aux_data_len: u8,
    pub multicast_address: std::net::Ipv6Addr,
    pub source_addresses: Vec<std::net::Ipv6Addr>,
    //pub aux_data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct MulticastListenerQuery {
    pub maximum_response_delay: u16,
    pub group_address: std::net::Ipv6Addr,
    pub supress_router_processing: bool,
    pub qrv: u8,
    pub qqic: u8,
    pub source_addresses: Vec<std::net::Ipv6Addr>,
}

#[derive(Debug, Clone)]
pub struct V1MulticastListenerReport {
    pub group_address: std::net::Ipv6Addr,
}

#[derive(Debug, Clone)]
pub struct V1MulticastListenerDone {
    pub group_address: std::net::Ipv6Addr,
}

#[derive(Debug, Clone)]
pub struct V2MulticastListenerReport {
    pub records: Vec<MulticastReportRecord>,
}

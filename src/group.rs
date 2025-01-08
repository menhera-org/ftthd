
pub struct MldSource {
    source_addr: std::net::Ipv6Addr,
    source_timer: u64,
}

pub type MldSources = std::collections::HashMap<std::net::Ipv6Addr, MldSource>;

pub enum MldMenbershipState {
    Include { include: MldSources },
    Exclude { include: MldSources, exclude: MldSources },
}

pub struct MldMembership {
    group_addr: std::net::Ipv6Addr,
    state: MldMenbershipState,
}

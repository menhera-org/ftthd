
#[derive(Clone)]
pub struct NdpOption {
    pub option_type: u8,
    pub option_data: Vec<u8>,
}

impl std::fmt::Debug for NdpOption {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.option_type {
            1 => {
                // Source Link-layer Address
                // MAC address format
                let value = self.option_data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":");
                write!(f, "src LL: {}", value)
            }

            2 => {
                // Target Link-layer Address
                // MAC address format
                let value = self.option_data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":");
                write!(f, "tgt LL: {}", value)
            }

            3 => {
                // prefix information
                write!(f, "prefix [{}]", self.option_data.len())
            }

            4 => {
                // Redirected Header
                write!(f, "redirected header [{}]", self.option_data.len())
            }

            5 => {
                // MTU
                write!(f, "MTU [{}]", self.option_data.len())
            }

            25 => {
                // Recursive DNS Server
                write!(f, "RDNSS [{}]", self.option_data.len())
            }

            31 => {
                // DNSSL
                write!(f, "DNSSL [{}]", self.option_data.len())
            }

            _ => {
                write!(f, "NdpOption({:#02x}) [{}]", self.option_type, self.option_data.len())
            }
        }
    }
}

fn fmt_option_list(f: &mut std::fmt::Formatter, options: &[NdpOption]) -> std::fmt::Result {
    let mut debug = f.debug_list();
    for option in options {
        debug.entry(&option);
    }
    debug.finish()
}

#[derive(Clone)]
pub struct RouterSolicitation {
    pub options: Vec<NdpOption>,
}

impl std::fmt::Debug for RouterSolicitation {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "NDP RouterSolicitation ")?;
        fmt_option_list(f, &self.options)
    }
}

#[derive(Clone)]
pub struct RouterAdvertisement {
    pub hop_limit: u8,
    pub managed_address_configuration: bool,
    pub other_configuration: bool,
    pub router_lifetime: u16,
    pub reachable_time: u32,
    pub retrans_timer: u32,
    pub options: Vec<NdpOption>,
}

impl std::fmt::Debug for RouterAdvertisement {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "NDP RouterAdvertisement: flags=")?;
        if self.managed_address_configuration {
            write!(f, "M")?;
        }
        if self.other_configuration {
            write!(f, "O")?;
        }

        write!(f, "hop_limit={}, ", self.hop_limit)?;
        write!(f, "router_lifetime={}, ", self.router_lifetime)?;
        write!(f, "reachable_time={}, ", self.reachable_time)?;
        write!(f, "retrans_timer={}, ", self.retrans_timer)?;
        fmt_option_list(f, &self.options)
    }
}

#[derive(Clone)]
pub struct NeighborSolicitation {
    pub target_address: std::net::Ipv6Addr,
    pub options: Vec<NdpOption>,
}

impl std::fmt::Debug for NeighborSolicitation {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "NDP NeighborSolicitation: {} ", self.target_address)?;
        fmt_option_list(f, &self.options)
    }
}

#[derive(Clone)]
pub struct NeighborAdvertisement {
    pub router: bool,
    pub solicited: bool,
    pub override_: bool,
    pub target_address: std::net::Ipv6Addr,
    pub options: Vec<NdpOption>,
}

impl std::fmt::Debug for NeighborAdvertisement {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "NDP NeighborAdvertisement: flags=")?;
        if self.router {
            write!(f, "R")?;
        }
        if self.solicited {
            write!(f, "S")?;
        }
        if self.override_ {
            write!(f, "O")?;
        }
        write!(f, " {} ", self.target_address)?;
        fmt_option_list(f, &self.options)
    }
}

#[derive(Clone)]
pub struct Redirect {
    pub target_address: std::net::Ipv6Addr,
    pub destination_address: std::net::Ipv6Addr,
    pub options: Vec<NdpOption>,
}

impl std::fmt::Debug for Redirect {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "NDP Redirect: target={} destination={} ", self.target_address, self.destination_address)?;
        fmt_option_list(f, &self.options)
    }
}

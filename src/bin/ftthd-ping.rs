
use std::sync::Arc;

fn main() {
    env_logger::init();
    let target = std::env::args().nth(1).expect("Usage: ftthd-ping <target>");
    let target: std::net::Ipv6Addr = target.parse().expect("Invalid IPv6 address");
    let socket = Arc::new(ftthd::icmp6::socket::RawIcmp6Socket::new().expect("Failed to create ICMPv6 socket"));
    socket.set_recv_hoplimit(true).expect("Failed to set recv hop limit");
    
    let identifier: u16 = rand::random();

    let recv_socket = socket.clone();
    std::thread::spawn(move || {
        let mut parser = ftthd::icmp6::Icmp6Parser::new();

        let expected_identifier = identifier;
        loop {
            recv_socket.recv_parser(&mut parser).expect("Failed to receive packet");
            let src_addr = parser.packet().target_addr;
            let ttl = parser.packet().hop_limit.unwrap().hop_limit;
            let parsed = parser.parse();
            match parsed {
                Ok(parsed) => {
                    match parsed {
                        ftthd::icmp6::Icmp6Packet::EchoReply { identifier, sequence, data } => {
                            if identifier != expected_identifier {
                                continue;
                            }
                            println!("Received echo reply from {}: ttl={}, sequence={}, datalen={}", src_addr, ttl, sequence, data.len());
                        }
                        _ => {}
                    }
                }
                Err(e) => {
                    log::debug!("Failed to parse packet: {:?}", e);
                }
            }
        }
    });

    let mut seq = 0;
    let mut writer = ftthd::icmp6::Icmp6Writer::new();
    loop {
        writer.set_destination(target);
        let packet = ftthd::icmp6::Icmp6Packet::EchoRequest { identifier, sequence: seq, data: vec![] };
        if let Err(e) = writer.set_packet(packet) {
            eprintln!("Failed to set packet: {:?}", e);
            return;
        }
        if let Err(e) = socket.send_writer(&writer) {
            eprintln!("Failed to send packet: {:?}", e);
        }

        seq += 1;
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

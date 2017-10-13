use std::net::Ipv4Addr;

use dhcp4r;

use structs::dhcp::*;
use structs::{self, CentrifugeError};


fn parse_dhcp_option(option: &dhcp4r::options::Option) -> Result<DhcpOption, ::std::string::FromUtf8Error> {
    use dhcp4r::options::*;
    let value = match option.code {

        REQUESTED_IP_ADDRESS |
        ROUTER |
        DOMAIN_NAME_SERVER => DhcpOption::IPv4(nbytes2ipv4(option.data).unwrap()),

        HOST_NAME => DhcpOption::String(String::from_utf8(option.data.to_vec())?),

        _ => DhcpOption::Bytes(option.data.to_vec()),
    };

    Ok(value)
}

fn wrap_packet(dhcp: dhcp4r::packet::Packet, packet: structs::dhcp::Packet) -> structs::dhcp::DHCP {
    use structs::dhcp::DHCP::*;

    match dhcp.option(dhcp4r::options::DHCP_MESSAGE_TYPE) {
        Some(msg_type) => {
            if msg_type.len() > 0 {
                match msg_type[0] {
                    dhcp4r::ACK => ACK(packet),
                    dhcp4r::DECLINE => DECLINE(packet),
                    dhcp4r::DISCOVER => DISCOVER(packet),
                    dhcp4r::INFORM => INFORM(packet),
                    dhcp4r::NAK => NAK(packet),
                    dhcp4r::OFFER => OFFER(packet),
                    dhcp4r::RELEASE => RELEASE(packet),
                    dhcp4r::REQUEST => REQUEST(packet),
                    _ => UNKNOWN(packet),
                }
            } else {
                UNKNOWN(packet)
            }
        },
        _ => UNKNOWN(packet),
    }
}


pub fn extract(remaining: &[u8]) -> Result<structs::dhcp::DHCP, CentrifugeError> {
    let dhcp = dhcp4r::packet::decode(remaining).unwrap();

    let ciaddr = bytes2ipv4(dhcp.ciaddr).unwrap();
    let yiaddr = bytes2ipv4(dhcp.yiaddr).unwrap();
    let siaddr = bytes2ipv4(dhcp.siaddr).unwrap();

    let mut packet = Packet::new(ciaddr, yiaddr, siaddr, dhcp.chaddr);

    for option in dhcp.options.iter() {
        if let Ok(value) = parse_dhcp_option(&option) {
            use dhcp4r::options::*;
            match option.code {
                HOST_NAME => packet.hostname = Some(value),
                REQUESTED_IP_ADDRESS => packet.requested_ip_address = Some(value),
                ROUTER => packet.router = Some(value),
                DOMAIN_NAME_SERVER => packet.domain_name_server = Some(value),
                _ => (),
            }
        }
    }

    Ok(wrap_packet(dhcp, packet))
}

fn bytes2ipv4(bytes: [u8; 4]) -> Option<Ipv4Addr> {
    if bytes.len() >= 4 {
        Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
    } else {
        None
    }
}

fn nbytes2ipv4(bytes: &[u8]) -> Option<Ipv4Addr> {
    if bytes.len() >= 4 {
        Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
    } else {
        None
    }
}

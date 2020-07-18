use crate::structs::dhcp::*;
use crate::structs::{self, CentrifugeError};

fn wrap_packet(dhcp: &dhcp4r::packet::Packet, packet: structs::dhcp::Packet) -> structs::dhcp::DHCP {
    use crate::structs::dhcp::DHCP::*;

    match dhcp.option(dhcp4r::options::DHCP_MESSAGE_TYPE) {
        Some(dhcp4r::options::DhcpOption::DhcpMessageType(msg_type)) => {
            match msg_type {
                dhcp4r::options::MessageType::Ack => ACK(packet),
                dhcp4r::options::MessageType::Decline => DECLINE(packet),
                dhcp4r::options::MessageType::Discover => DISCOVER(packet),
                dhcp4r::options::MessageType::Inform => INFORM(packet),
                dhcp4r::options::MessageType::Nak => NAK(packet),
                dhcp4r::options::MessageType::Offer => OFFER(packet),
                dhcp4r::options::MessageType::Release => RELEASE(packet),
                dhcp4r::options::MessageType::Request => REQUEST(packet),
            }
        }
        _ => UNKNOWN(packet),
    }
}


pub fn extract(remaining: &[u8]) -> Result<structs::dhcp::DHCP, CentrifugeError> {

    let dhcp = match dhcp4r::packet::Packet::from(remaining) {
        Ok(dhcp) => dhcp,
        Err(_err) => return Err(CentrifugeError::InvalidPacket),
    };

    let mut packet = Packet::new(dhcp.ciaddr, dhcp.yiaddr, dhcp.siaddr, dhcp.chaddr);

    for option in &dhcp.options {
        use dhcp4r::options::*;
        match option {
            DhcpOption::RequestedIpAddress(addr) => packet.requested_ip_address = Some(*addr),
            DhcpOption::HostName(hostname) => packet.hostname = Some(hostname.to_string()),
            DhcpOption::Router(router) => packet.router = Some(router.to_vec()),
            DhcpOption::DomainNameServer(server) => packet.domain_name_server = Some(server.to_vec()),
            _ => (),
        }
    }

    Ok(wrap_packet(&dhcp, packet))
}

use std::str::from_utf8;

use nom::IResult::Done;
use pktparse::udp;

use centrifuge::dns;
use centrifuge::dhcp;

use structs::CentrifugeError;
use structs::udp::UDP;


pub fn extract(remaining: &[u8]) -> Result<(udp::UdpHeader, UDP), CentrifugeError> {
    if let Done(remaining, udp_hdr) = udp::parse_udp_header(remaining) {
        if remaining.is_empty() {
            return Err(CentrifugeError::InvalidPacket);
        }

        if udp_hdr.dest_port == 53 || udp_hdr.source_port == 53 {
            let dns = dns::extract(remaining)?;
            Ok((udp_hdr, UDP::DNS(dns)))
        } else if (udp_hdr.dest_port == 67 && udp_hdr.source_port == 68) ||
                   (udp_hdr.dest_port == 68 && udp_hdr.source_port == 67)
        {
            let dhcp = dhcp::extract(remaining)?;
            Ok((udp_hdr, UDP::DHCP(dhcp)))
        } else {
            // if slice contains null bytes, don't try to decode
            if remaining.contains(&0) {
                Ok((udp_hdr, UDP::Binary(remaining.to_vec())))
            } else {
                match from_utf8(remaining) {
                    Ok(remaining) => Ok((udp_hdr, UDP::Text(remaining.to_owned()))),
                    Err(_) => Ok((udp_hdr, UDP::Binary(remaining.to_vec()))),
                }
            }
        }
    } else {
        Err(CentrifugeError::InvalidPacket)
    }
}

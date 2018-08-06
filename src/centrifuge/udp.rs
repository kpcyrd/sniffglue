use std::str::from_utf8;

use pktparse::udp::{self, UdpHeader};

use centrifuge::dns;
use centrifuge::dhcp;
use centrifuge::ssdp;
use centrifuge::dropbox;

use structs::CentrifugeError;
use structs::udp::UDP;


pub fn parse(remaining: &[u8]) -> Result<(udp::UdpHeader, UDP), CentrifugeError> {
    if let Ok((remaining, udp_hdr)) = udp::parse_udp_header(remaining) {
        let inner = match extract(&udp_hdr, remaining) {
            Ok(x) => x,
            Err(_) => unknown(remaining),
        };
        Ok((udp_hdr, inner))
    } else {
        Err(CentrifugeError::InvalidPacket)
    }
}

#[inline]
pub fn extract(udp_hdr: &UdpHeader, remaining: &[u8]) -> Result<UDP, CentrifugeError> {
    if remaining.is_empty() {
        Ok(UDP::Binary(Vec::new()))
    } else if udp_hdr.dest_port == 53 || udp_hdr.source_port == 53 {
        let dns = dns::extract(remaining)?;
        Ok(UDP::DNS(dns))
    } else if (udp_hdr.dest_port == 67 && udp_hdr.source_port == 68) ||
               (udp_hdr.dest_port == 68 && udp_hdr.source_port == 67)
    {
        let dhcp = dhcp::extract(remaining)?;
        Ok(UDP::DHCP(dhcp))
    } else if udp_hdr.source_port == 17500 && udp_hdr.dest_port == 17500 {
        let dropbox = dropbox::extract(remaining)?;
        Ok(UDP::Dropbox(dropbox))
    } else {
        Err(CentrifugeError::UnknownProtocol)
    }
}

#[inline]
pub fn unknown(remaining: &[u8]) -> UDP {
    // if slice contains null bytes, don't try to decode
    if remaining.contains(&0) {
        UDP::Binary(remaining.to_vec())
    } else {
        match from_utf8(remaining) {
            Ok(remaining) => {
                if let Ok(ssdp) = ssdp::parse_ssdp(remaining) {
                    UDP::SSDP(ssdp)
                } else {
                    UDP::Text(remaining.to_owned())
                }
            }
            Err(_) => UDP::Binary(remaining.to_vec()),
        }
    }
}

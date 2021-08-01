use pktparse::icmp;

use crate::structs::CentrifugeError;
use crate::structs::icmp::ICMP;

pub fn parse(remaining: &[u8]) -> Result<(icmp::IcmpHeader, ICMP), CentrifugeError> {
    if let Ok((remaining, icmp_hdr)) = icmp::parse_icmp_header(remaining) {
        Ok((icmp_hdr, ICMP {
            data: remaining.to_vec(),
        }))
    } else {
        Err(CentrifugeError::InvalidPacket)
    }
}

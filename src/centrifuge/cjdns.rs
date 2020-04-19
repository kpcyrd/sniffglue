use crate::structs::{cjdns, CentrifugeError};
use nom::be_u16;

const BEACON_PASSWORD_LEN: usize = 20;
const BEACON_PUBKEY_LEN: usize = 32;


named!(cjdns_eth_header<&[u8], cjdns::CjdnsEthPkt>, do_parse!(
    _version:       tag!(b"\x00") >>
    _zero:          tag!(b"\x00") >>
    _length:        be_u16 >>
    _fc00:          tag!(b"\xfc\x00") >>
    _padding:       take!(2) >>

    version:        be_u16 >>
    password:       take!(BEACON_PASSWORD_LEN) >>
    pubkey:         take!(BEACON_PUBKEY_LEN) >>

    ({ cjdns::CjdnsEthPkt {
        version,
        password: password.to_vec(),
        pubkey: pubkey.to_vec(),
    } })
));

pub fn parse(remaining: &[u8]) -> Result<cjdns::CjdnsEthPkt, CentrifugeError> {
    if let Ok((remaining, cjdns_eth_hdr)) = cjdns_eth_header(remaining) {
        if remaining.is_empty() {
            Ok(cjdns_eth_hdr)
        } else {
            Err(CentrifugeError::InvalidPacket)
        }
    } else {
        Err(CentrifugeError::InvalidPacket)
    }
}

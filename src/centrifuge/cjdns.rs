use crate::structs::{cjdns, CentrifugeError};
use nom::number::complete::be_u16;
use nom::bytes::complete::{tag, take};

const BEACON_PASSWORD_LEN: usize = 20;
const BEACON_PUBKEY_LEN: usize = 32;


fn cjdns_eth_header(input: &[u8]) -> nom::IResult<&[u8], cjdns::CjdnsEthPkt> {
    let (input, (
        _version,
        _zero,
        _length,
        _fc00,
        _padding,
        version,
        password,
        pubkey,
    )) = nom::sequence::tuple((
        tag(b"\x00"),
        tag(b"\x00"),
        be_u16,
        tag(b"\xfc\x00"),
        take(2_usize),

        be_u16,
        take(BEACON_PASSWORD_LEN),
        take(BEACON_PUBKEY_LEN),
    ))(input)?;

    Ok((input, cjdns::CjdnsEthPkt {
        version,
        password: password.to_vec(),
        pubkey: pubkey.to_vec(),
    }))
}

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

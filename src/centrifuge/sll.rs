use crate::centrifuge::{parse_ipv4, parse_ipv6};
use crate::structs::ether::Ether;
use crate::structs::CentrifugeError;
use nom::bytes::complete::take;
use nom::number::complete::be_u16;

struct CookedCaptureHeader {
    protocol: u16,
}

fn parse_cooked_capture_hdr(remaining: &[u8]) -> nom::IResult<&[u8], CookedCaptureHeader> {
    let (remaining, _pkt_type) = be_u16(remaining)?;
    let (remaining, _addr_type) = be_u16(remaining)?;
    let (remaining, _addr_len) = be_u16(remaining)?;
    let (remaining, _unused) = take(8_usize)(remaining)?;
    let (remaining, protocol) = be_u16(remaining)?;

    Ok((remaining, CookedCaptureHeader { protocol }))
}

pub fn parse(remaining: &[u8]) -> Result<Ether, CentrifugeError> {
    if let Ok((remaining, ssl_hdr)) = parse_cooked_capture_hdr(remaining) {
        match ssl_hdr.protocol {
            0x0800 => parse_ipv4(remaining),
            0x86DD => parse_ipv6(remaining),
            _ => Err(CentrifugeError::UnknownProtocol),
        }
    } else {
        Err(CentrifugeError::InvalidPacket)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structs::ipv4::IPv4;
    use crate::structs::tcp::TCP;
    use pktparse::ip::IPProtocol;
    use pktparse::ipv4::IPv4Header;
    use pktparse::tcp::TcpHeader;

    #[test]
    fn parse_ppp_tcp() {
        let pkt = &[
            0, 4, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 69, 0, 0, 94, 246, 185, 64, 0, 64, 6,
            207, 208, 116, 210, 112, 45, 101, 229, 41, 43, 207, 129, 84, 13, 198, 148, 181, 0, 43,
            213, 120, 197, 128, 24, 10, 79, 191, 153, 0, 0, 1, 1, 8, 10, 142, 74, 43, 3, 135, 14,
            204, 87, 0, 40, 78, 0, 0, 0, 0, 0, 3, 251, 177, 252, 25, 181, 4, 23, 100, 102, 211,
            164, 79, 192, 232, 227, 130, 103, 52, 17, 8, 4, 169, 136, 247, 108, 69, 53, 165, 67,
            201, 73, 66, 79,
        ];
        let eth = parse(pkt).unwrap();
        assert_eq!(
            eth,
            Ether::IPv4(
                IPv4Header {
                    version: 4,
                    ihl: 5,
                    tos: 0,
                    length: 94,
                    id: 63161,
                    flags: 2,
                    fragment_offset: 0,
                    ttl: 64,
                    protocol: IPProtocol::TCP,
                    chksum: 53200,
                    source_addr: "116.210.112.45".parse().unwrap(),
                    dest_addr: "101.229.41.43".parse().unwrap(),
                },
                IPv4::TCP(
                    TcpHeader {
                        source_port: 53121,
                        dest_port: 21517,
                        sequence_no: 3331634432,
                        ack_no: 735410373,
                        data_offset: 8,
                        reserved: 0,
                        flag_urg: false,
                        flag_ack: true,
                        flag_psh: true,
                        flag_rst: false,
                        flag_syn: false,
                        flag_fin: false,
                        window: 2639,
                        checksum: 49049,
                        urgent_pointer: 0,
                        options: None,
                    },
                    TCP::Binary(vec![
                        0, 40, 78, 0, 0, 0, 0, 0, 3, 251, 177, 252, 25, 181, 4, 23, 100, 102, 211,
                        164, 79, 192, 232, 227, 130, 103, 52, 17, 8, 4, 169, 136, 247, 108, 69, 53,
                        165, 67, 201, 73, 66, 79
                    ],)
                )
            )
        );
    }
}

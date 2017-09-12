use nom::IResult::Done;
use pktparse::{ethernet, ipv4};
use pktparse::ipv4::IPv4Protocol;
use pktparse::ethernet::EtherType;

use structs::prelude::*;
use structs::CentrifugeError;
use structs::raw;

pub mod tcp;
pub mod udp;

pub mod dhcp;
pub mod dns;
pub mod http;
pub mod tls;


pub fn parse(data: &[u8]) -> Result<raw::Raw, CentrifugeError> {
    if let Done(remaining, eth_frame) = ethernet::parse_ethernet_frame(data) {
        match eth_frame.ethertype {
            EtherType::IPv4 => {
                if let Done(remaining, ip_hdr) = ipv4::parse_ipv4_header(remaining) {
                    match ip_hdr.protocol {
                        IPv4Protocol::TCP => {
                            let (tcp_hdr, tcp) = tcp::extract(remaining)?;
                            Ok(Ether(eth_frame, IPv4(ip_hdr, TCP(tcp_hdr, tcp))))
                        },
                        IPv4Protocol::UDP => {
                            let (udp_hdr, udp) = udp::extract(remaining)?;
                            Ok(Ether(eth_frame, IPv4(ip_hdr, UDP(udp_hdr, udp))))
                        },
                        _ => Err(CentrifugeError::UnknownProtocol),
                    }
                } else {
                    Err(CentrifugeError::InvalidPacket)
                }
            },
            EtherType::IPv6 => {
                // TODO
                Err(CentrifugeError::UnknownProtocol)
            },
            EtherType::ARP => {
                // TODO
                Err(CentrifugeError::UnknownProtocol)
            },
            _ => Err(CentrifugeError::UnknownProtocol),
        }
    } else {
        Err(CentrifugeError::InvalidPacket)
    }
}

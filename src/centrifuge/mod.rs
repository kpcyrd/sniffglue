use nom::IResult::Done;
use pktparse::{ethernet, ipv4};
use pktparse::ipv4::IPv4Protocol;
use pktparse::ethernet::EtherType;

use structs::prelude::*;
use structs::CentrifugeError;
use structs::raw;
use structs::ether::{self, Ether};
use structs::ipv4::IPv4;
use link::DataLink;

pub mod arp;
pub mod tcp;
pub mod udp;

pub mod dhcp;
pub mod dns;
pub mod ssdp;
pub mod http;
pub mod tls;


#[inline]
pub fn parse(link: &DataLink, data: &[u8]) -> raw::Raw {
    use structs::raw::Raw::Unknown;
    match *link {
        DataLink::Ethernet => match parse_eth(data) {
            Ok(eth) => eth,
            Err(_)  => Unknown(data.to_vec()),
        },
        DataLink::Tun => parse_tun(data),
        DataLink::RadioTap => {
            Unknown(data.to_vec())
        },
    }
}

#[inline]
pub fn parse_eth(data: &[u8]) -> Result<raw::Raw, CentrifugeError> {
    use structs::ether::Ether::Unknown;
    if let Done(remaining, eth_frame) = ethernet::parse_ethernet_frame(data) {
        let inner = match eth_frame.ethertype {
            EtherType::IPv4 => match parse_ipv4(remaining) {
                Ok(ipv4) => ipv4,
                Err(_)   => Unknown(remaining.to_vec()),
            },
            EtherType::IPv6 => {
                // TODO
                Unknown(remaining.to_vec())
            },
            EtherType::ARP => match arp::extract(remaining) {
                Ok(arp_pkt) => Arp(arp_pkt),
                Err(_)      => Unknown(remaining.to_vec()),
            },
            _ => {
                Unknown(remaining.to_vec())
            },
        };
        Ok(Ether(eth_frame, inner))
    } else {
        Err(CentrifugeError::InvalidPacket)
    }
}

#[inline]
pub fn parse_tun(data: &[u8]) -> raw::Raw {
    raw::Raw::Tun(
        if let Ok(ipv4) = parse_ipv4(data) {
            ipv4
        } else {
            Ether::Unknown(data.to_vec())
        }
    )
}

#[inline]
pub fn parse_ipv4(data: &[u8]) -> Result<ether::Ether, CentrifugeError> {
    if let Done(remaining, ip_hdr) = ipv4::parse_ipv4_header(data) {
        let inner = match ip_hdr.protocol {
            IPv4Protocol::TCP => match tcp::parse(remaining) {
                Ok((tcp_hdr, tcp)) => TCP(tcp_hdr, tcp),
                Err(_) => IPv4::Unknown(remaining.to_vec()),
            },
            IPv4Protocol::UDP => match udp::parse(remaining) {
                Ok((udp_hdr, udp)) => UDP(udp_hdr, udp),
                Err(_) => IPv4::Unknown(remaining.to_vec()),
            },
            _ => {
                IPv4::Unknown(remaining.to_vec())
            }
        };
        Ok(IPv4(ip_hdr, inner))
    } else {
        Ok(Ether::Unknown(data.to_vec()))
    }
}

use pktparse::{ethernet, ipv4, ipv6};
use pktparse::ip::IPProtocol;
use pktparse::ethernet::EtherType;

use crate::structs::prelude::*;
use crate::structs::CentrifugeError;
use crate::structs::raw;
use crate::structs::ether::{self, Ether};
use crate::link::DataLink;

pub mod arp;
pub mod tcp;
pub mod udp;
pub mod icmp;
pub mod cjdns;
pub mod sll;

pub mod dhcp;
pub mod dns;
pub mod ssdp;
pub mod dropbox;
pub mod http;
pub mod tls;


#[inline]
pub fn parse(link: &DataLink, data: &[u8]) -> raw::Raw {
    match *link {
        DataLink::Ethernet => match parse_eth(data) {
            Ok(eth) => eth,
            Err(_)  => Unknown(data.to_vec()),
        },
        DataLink::Tun => parse_tun(data),
        DataLink::Sll => parse_sll(data),
        DataLink::RadioTap => {
            Unknown(data.to_vec())
        },
    }
}

#[inline]
pub fn parse_eth(data: &[u8]) -> Result<raw::Raw, CentrifugeError> {
    use crate::structs::ether::Ether::Unknown;
    if let Ok((remaining, eth_frame)) = ethernet::parse_ethernet_frame(data) {
        let inner = match eth_frame.ethertype {
            EtherType::IPv4 => match parse_ipv4(remaining) {
                Ok(ipv4) => ipv4,
                Err(_)   => Unknown(remaining.to_vec()),
            },
            EtherType::IPv6 => match parse_ipv6(remaining) {
                Ok(ipv6) => ipv6,
                Err(_)   => Unknown(remaining.to_vec()),
            },
            EtherType::ARP => match arp::extract(remaining) {
                Ok(arp_pkt) => Arp(arp_pkt),
                Err(_)      => Unknown(remaining.to_vec()),
            },
            EtherType::Other(0xfc00) => match cjdns::parse(remaining) {
                Ok(cjdns_pkt) => Cjdns(cjdns_pkt),
                Err(_)        => Unknown(remaining.to_vec()),
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

pub fn parse_sll(data: &[u8]) -> raw::Raw {
    raw::Raw::Sll(
        if let Ok(frame) = sll::parse(data) {
            frame
        } else {
            Ether::Unknown(data.to_vec())
        }
    )
}

#[inline]
pub fn parse_ipv4(data: &[u8]) -> Result<ether::Ether, CentrifugeError> {
    use crate::structs::ipv4::IPv4::*;

    if let Ok((remaining, ip_hdr)) = ipv4::parse_ipv4_header(data) {
        let inner = match ip_hdr.protocol {
            IPProtocol::TCP => match tcp::parse(remaining) {
                Ok((tcp_hdr, tcp)) => TCP(tcp_hdr, tcp),
                Err(_) => Unknown(remaining.to_vec()),
            },
            IPProtocol::UDP => match udp::parse(remaining) {
                Ok((udp_hdr, udp)) => UDP(udp_hdr, udp),
                Err(_) => Unknown(remaining.to_vec()),
            },
            IPProtocol::ICMP => match icmp::parse(remaining) {
                Ok((icmp_hdr, icmp)) => ICMP(icmp_hdr, icmp),
                Err(_) => Unknown(remaining.to_vec()),
            },
            _ => {
                Unknown(remaining.to_vec())
            }
        };
        Ok(IPv4(ip_hdr, inner))
    } else {
        Ok(Ether::Unknown(data.to_vec()))
    }
}

#[inline]
pub fn parse_ipv6(data: &[u8]) -> Result<ether::Ether, CentrifugeError> {
    use crate::structs::ipv6::IPv6::*;

    if let Ok((remaining, ip_hdr)) = ipv6::parse_ipv6_header(data) {
        let inner = match ip_hdr.next_header {
            IPProtocol::TCP => match tcp::parse(remaining) {
                Ok((tcp_hdr, tcp)) => TCP(tcp_hdr, tcp),
                Err(_) => Unknown(remaining.to_vec()),
            },
            IPProtocol::UDP => match udp::parse(remaining) {
                Ok((udp_hdr, udp)) => UDP(udp_hdr, udp),
                Err(_) => Unknown(remaining.to_vec()),
            },
            _ => {
                Unknown(remaining.to_vec())
            }
        };
        Ok(IPv6(ip_hdr, inner))
    } else {
        Ok(Ether::Unknown(data.to_vec()))
    }
}

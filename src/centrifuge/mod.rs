use nom::IResult::Done;
use pktparse::{ethernet, ipv4};
use pktparse::ipv4::IPv4Protocol;
use pktparse::ethernet::EtherType;

use structs::prelude::*;
use structs::CentrifugeError;
use structs::raw;
use structs::ether;
use link::DataLink;

pub mod arp;
pub mod tcp;
pub mod udp;

pub mod dhcp;
pub mod dns;
pub mod http;
pub mod tls;


#[inline]
pub fn parse(link: &DataLink, data: &[u8]) -> Result<raw::Raw, CentrifugeError> {
    match *link {
        DataLink::Ethernet => parse_eth(data),
        DataLink::Tun => parse_tun(data)
                                .map(|x| raw::Raw::Tun(x)),
        DataLink::RadioTap => {
            unimplemented!()
        },
    }
}

#[inline]
pub fn parse_eth(data: &[u8]) -> Result<raw::Raw, CentrifugeError> {
    if let Done(remaining, eth_frame) = ethernet::parse_ethernet_frame(data) {
        match eth_frame.ethertype {
            EtherType::IPv4 => parse_ipv4(remaining)
                .map(|ip| Ether(eth_frame, ip)),
            EtherType::IPv6 => {
                // TODO
                Err(CentrifugeError::UnknownProtocol)
            },
            EtherType::ARP => {
                let arp_pkt = arp::extract(remaining)?;
                Ok(Ether(eth_frame, Arp(arp_pkt)))
            },
            _ => Err(CentrifugeError::UnknownProtocol),
        }
    } else {
        Err(CentrifugeError::InvalidPacket)
    }
}

#[inline]
pub fn parse_tun(data: &[u8]) -> Result<ether::Ether, CentrifugeError> {
    if let Ok(ipv4) = parse_ipv4(data) {
        Ok(ipv4)
    } else {
        Err(CentrifugeError::InvalidPacket)
    }
}

#[inline]
pub fn parse_ipv4(data: &[u8]) -> Result<ether::Ether, CentrifugeError> {
    if let Done(remaining, ip_hdr) = ipv4::parse_ipv4_header(data) {
        match ip_hdr.protocol {
            IPv4Protocol::TCP => {
                let (tcp_hdr, tcp) = tcp::extract(remaining)?;
                Ok(IPv4(ip_hdr, TCP(tcp_hdr, tcp)))
            },
            IPv4Protocol::UDP => {
                let (udp_hdr, udp) = udp::extract(remaining)?;
                Ok(IPv4(ip_hdr, UDP(udp_hdr, udp)))
            },
            _ => Err(CentrifugeError::UnknownProtocol),
        }
    } else {
        Err(CentrifugeError::InvalidPacket)
    }
}

use crate::structs::arp;
use crate::structs::ipv4;
use crate::structs::ipv6;
use crate::structs::cjdns;
use crate::structs::NoiseLevel;
use serde::Serialize;

#[derive(Debug, PartialEq, Serialize)]
pub enum Ether {
    Arp(arp::ARP),
    IPv4(pktparse::ipv4::IPv4Header, ipv4::IPv4),
    IPv6(pktparse::ipv6::IPv6Header, ipv6::IPv6),
    Cjdns(cjdns::CjdnsEthPkt),
    Unknown(Vec<u8>),
}

impl Ether {
    pub fn noise_level(&self) -> NoiseLevel {
        use self::Ether::*;
        match *self {
            Arp(_) => NoiseLevel::One,
            IPv4(_, ref ipv4) => ipv4.noise_level(),
            IPv6(_, ref ipv6) => ipv6.noise_level(),
            Cjdns(_) => NoiseLevel::Two,
            Unknown(_) => NoiseLevel::Maximum,
        }
    }
}

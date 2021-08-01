use crate::structs::{tcp, udp, icmp};
use crate::structs::NoiseLevel;
use serde::Serialize;

#[derive(Debug, PartialEq, Serialize)]
pub enum IPv4 {
    TCP(pktparse::tcp::TcpHeader, tcp::TCP),
    UDP(pktparse::udp::UdpHeader, udp::UDP),
    ICMP(pktparse::icmp::IcmpHeader, icmp::ICMP),
    Unknown(Vec<u8>),
}

impl IPv4 {
    pub fn noise_level(&self) -> NoiseLevel {
        use self::IPv4::*;
        match *self {
            TCP(ref header, ref tcp) => tcp.noise_level(header),
            UDP(_, ref udp) => udp.noise_level(),
            ICMP(ref header, ref icmp) => icmp.noise_level(header),
            Unknown(_) => NoiseLevel::Maximum,
        }
    }
}

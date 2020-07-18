use crate::structs::ether;
use crate::structs::NoiseLevel;
use serde::Serialize;

#[derive(Debug, PartialEq, Serialize)]
pub enum Raw {
    Ether(pktparse::ethernet::EthernetFrame, ether::Ether),
    Tun(ether::Ether),
    Unknown(Vec<u8>),
}

impl Raw {
    pub fn noise_level(&self) -> NoiseLevel {
        use self::Raw::*;
        match *self {
            Ether(_, ref ether) => ether.noise_level(),
            Tun(ref ether) => ether.noise_level(),
            Unknown(_) => NoiseLevel::Maximum,
        }
    }
}

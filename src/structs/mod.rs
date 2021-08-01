#[derive(Debug, PartialEq)]
pub enum CentrifugeError {
    WrongProtocol,
    ParsingError,

    UnknownProtocol,
    InvalidPacket,
}

pub mod prelude {
    pub use crate::structs::raw::Raw::*;
    pub use crate::structs::ether::Ether::*;
}

/// `Zero`            - This packet is very interesting
/// `One`             - This packet is somewhat interesting
/// `Two`             - Stuff you want to see if you're looking really hard
/// `AlmostMaximum`   - Some binary data
/// `Maximum`         - We couldn't parse this
#[derive(Debug)]
pub enum NoiseLevel {
    Zero          = 0,
    One           = 1,
    Two           = 2,
    AlmostMaximum = 3,
    Maximum       = 4,
}

impl NoiseLevel {
    pub fn into_u8(self) -> u8 {
        self as u8
    }
}

pub mod raw;
pub mod ether;
pub mod arp;
pub mod cjdns;
pub mod icmp;
pub mod ipv4;
pub mod ipv6;
pub mod ip;
pub mod tcp;
pub mod udp;
pub mod tls;
pub mod http;
pub mod dhcp;
pub mod dns;
pub mod ssdp;
pub mod dropbox;

use crate::structs::dns;
use crate::structs::dhcp;
use crate::structs::ssdp;
use crate::structs::dropbox;
use crate::structs::NoiseLevel;
use serde::Serialize;

#[derive(Debug, PartialEq, Serialize)]
pub enum UDP {
    DHCP(dhcp::DHCP),
    DNS(dns::DNS),
    SSDP(ssdp::SSDP),
    Dropbox(dropbox::DropboxBeacon),

    Text(String),
    Binary(Vec<u8>),
}

impl UDP {
    pub fn noise_level(&self) -> NoiseLevel {
        use self::UDP::*;
        match *self {
            DHCP(_) => NoiseLevel::Zero,
            DNS(_) => NoiseLevel::Zero,
            SSDP(_) => NoiseLevel::Two,
            Dropbox(_) => NoiseLevel::Two,
            Text(_) => NoiseLevel::Two,
            Binary(_) => NoiseLevel::AlmostMaximum,
        }
    }
}

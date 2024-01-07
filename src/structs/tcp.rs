use crate::structs::tls;
use crate::structs::http;
use crate::structs::NoiseLevel;
use serde::Serialize;

#[derive(Debug, PartialEq, Serialize)]
pub enum TCP {
    TLS(tls::TLS),
    HTTP(http::Http),

    Text(String),
    Binary(Vec<u8>),
    Empty,
}

impl TCP {
    pub fn noise_level(&self, header: &pktparse::tcp::TcpHeader) -> NoiseLevel {
        use self::TCP::*;

        if header.flag_rst || header.flag_syn || header.flag_fin {
            // control packet
            match *self {
                Text(_) => NoiseLevel::Two,
                Binary(_) => NoiseLevel::Two,
                Empty => NoiseLevel::Two,
                _ => NoiseLevel::Zero,
            }
        } else {
            // data packet
            match *self {
                Text(ref text) if text.len() <= 8 => NoiseLevel::AlmostMaximum,
                Binary(_) => NoiseLevel::AlmostMaximum,
                Empty => NoiseLevel::AlmostMaximum,
                _ => NoiseLevel::Zero,
            }
        }
    }
}

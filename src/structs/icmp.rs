use crate::structs::NoiseLevel;
use pktparse::icmp::{IcmpHeader, IcmpCode};
use serde::Serialize;

#[derive(Debug, PartialEq, Serialize)]
pub struct ICMP {
    pub data: Vec<u8>,
}

impl ICMP {
    pub fn noise_level(&self, header: &IcmpHeader) -> NoiseLevel {
        match header.code {
            IcmpCode::EchoReply => NoiseLevel::One,
            /*
            IcmpCode::Reserved,
            IcmpCode::DestinationUnreachable(_) =>
            IcmpCode::DestinationUnreachable(Unreachable),
            IcmpCode::SourceQuench,
            IcmpCode::Redirect(Redirect),
            */
            IcmpCode::EchoRequest => NoiseLevel::One,
            /*
            IcmpCode::RouterAdvertisment,
            IcmpCode::RouterSolicication,
            IcmpCode::TimeExceeded(_) => NoiseLevel::One,
            IcmpCode::ParameterProblem(ParameterProblem),
            IcmpCode::Timestamp,
            IcmpCode::TimestampReply,
            IcmpCode::ExtendedEchoRequest,
            IcmpCode::ExtendedEchoReply(ExtendedEchoReply),
            IcmpCode::Other(u16)
            */
            _ => NoiseLevel::Two,
        }
    }
}

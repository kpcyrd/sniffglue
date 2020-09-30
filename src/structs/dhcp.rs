use serde::Serialize;
use std::net::Ipv4Addr;

#[derive(Debug, PartialEq, Serialize)]
pub enum DHCP {
    ACK(Packet),
    DECLINE(Packet),
    DISCOVER(Packet),
    INFORM(Packet),
    NAK(Packet),
    OFFER(Packet),
    RELEASE(Packet),
    REQUEST(Packet),
    UNKNOWN(Packet),
}

#[derive(Debug, PartialEq, Serialize)]
pub struct Packet {
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub chaddr: [u8; 6],

    pub hostname: Option<String>,
    pub requested_ip_address: Option<Ipv4Addr>,
    pub router: Option<Vec<Ipv4Addr>>,
    pub domain_name_server: Option<Vec<Ipv4Addr>>,
}

impl Packet {
    pub fn new(ciaddr: Ipv4Addr, yiaddr: Ipv4Addr, siaddr: Ipv4Addr, chaddr: [u8; 6]) -> Packet {
        Packet {
            ciaddr,
            yiaddr,
            siaddr,
            chaddr,

            hostname: None,
            requested_ip_address: None,
            router: None,
            domain_name_server: None,
        }
    }
}

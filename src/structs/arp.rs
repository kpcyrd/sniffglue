use serde::Serialize;

#[derive(Debug, PartialEq, Serialize)]
pub enum ARP {
    Request(pktparse::arp::ArpPacket),
    Reply(pktparse::arp::ArpPacket),
}

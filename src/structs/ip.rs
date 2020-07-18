use pktparse::{ipv4, ipv6};
use std::fmt::Display;
use std::net::Ipv4Addr;

pub trait IPHeader {
    type Addr: Display;

    fn source_addr(&self) -> Self::Addr;
    fn dest_addr(&self) -> Self::Addr;
}

impl IPHeader for ipv4::IPv4Header {
    type Addr = Ipv4Addr;

    #[inline]
    fn source_addr(&self) -> Self::Addr {
        self.source_addr
    }

    #[inline]
    fn dest_addr(&self) -> Self::Addr {
        self.dest_addr
    }
}

impl IPHeader for ipv6::IPv6Header {
    type Addr = String;

    #[inline]
    fn source_addr(&self) -> Self::Addr {
        format!("[{}]", self.source_addr)
    }

    #[inline]
    fn dest_addr(&self) -> Self::Addr {
        format!("[{}]", self.dest_addr)
    }
}

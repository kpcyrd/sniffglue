use std::sync::Arc;

use pktparse;
use reduce::Reduce;
use ansi_term::Colour::{self, Yellow, Blue, Green, Red, Purple};
use serde_json;

use structs::ether;
use structs::arp;
use structs::ipv4;
use structs::tcp;
use structs::udp;
use structs::raw::Raw;
use structs::prelude::*;
use structs::dhcp::DhcpOption;


pub struct Config {
    fmt: Format,
    filter: Arc<Filter>,
}

impl Config {
    pub fn new(layout: Layout, verbose: u64, colors: bool) -> Config {
        Config {
            fmt: Format::new(layout, colors),
            filter: Arc::new(Filter::new(verbose)),
        }
    }

    pub fn filter(&self) -> Arc<Filter> {
        self.filter.clone()
    }

    pub fn format(self) -> Format {
        self.fmt
    }
}

pub enum Layout {
    Compact,
    Detailed,
    Json,
}

pub struct Format {
    layout: Layout,
    colors: bool,
}

impl Format {
    pub fn new(layout: Layout, colors: bool) -> Format {
        Format {
            layout,
            colors,
        }
    }

    #[inline]
    pub fn print(&self, packet: Raw) {
        match self.layout {
            Layout::Compact => self.print_compact(packet),
            Layout::Detailed => self.print_detailed(packet),
            Layout::Json => self.print_json(&packet),
        }
    }

    #[inline]
    fn colorify(&self, color: Colour, out: String) -> String {
        if self.colors {
            color.normal().paint(out).to_string()
        } else {
            out
        }
    }

    #[inline]
    fn print_compact(&self, packet: Raw) {
        let mut out = String::new();

        use structs::raw::Raw::Unknown;
        let color = match packet {
            Ether(eth_frame, eth) => {
                out += &format!("{} -> {}, ",
                                display_macaddr(&eth_frame.source_mac),
                                display_macaddr(&eth_frame.dest_mac));

                self.format_compact_eth(&mut out, eth)
            },
            Tun(eth) => self.format_compact_eth(&mut out, eth),
            Unknown(data) => self.format_compact_unknown_data(&mut out, &data),
        };

        println!("{}", match color {
            Some(color) => self.colorify(color, out),
            None => out,
        });
    }

    #[inline]
    fn format_compact_unknown_data(&self, out: &mut String, data: &[u8]) -> Option<Colour> {
        out.push_str(&format!("[unknown] {:?}", data));
        None
    }

    #[inline]
    fn format_compact_eth(&self, out: &mut String, eth: ether::Ether) -> Option<Colour> {
        match eth {
            Arp(arp_pkt) => self.format_compact_arp(out, arp_pkt),
            IPv4(ip_hdr, TCP(tcp_hdr, tcp)) => self.format_compact_ipv4_tcp(out, ip_hdr, tcp_hdr, tcp),
            IPv4(ip_hdr, UDP(udp_hdr, udp)) => self.format_compact_ipv4_udp(out, ip_hdr, udp_hdr, udp),
            IPv4(ip_hdr, ipv4::IPv4::Unknown(data)) => self.format_compact_ipv4_unknown(out, ip_hdr, &data),
            ether::Ether::Unknown(data) => self.format_compact_unknown_data(out, &data),
        }
    }

    #[inline]
    fn format_compact_arp(&self, out: &mut String, arp_pkt: arp::ARP) -> Option<Colour> {
        use structs::arp::ARP;
        out.push_str(&match arp_pkt {
            ARP::Request(arp_pkt) => {
                format!("[arp/request] who has {:15}? (tell {}, {})",
                    format!("{}", arp_pkt.dest_addr),
                    format!("{}", arp_pkt.src_addr),
                    display_macaddr(&arp_pkt.src_mac))
            },
            ARP::Reply(arp_pkt) => {
                format!("[arp/reply] {:15} => {} (fyi {}, {})",
                    format!("{}", arp_pkt.src_addr),
                    display_macaddr(&arp_pkt.src_mac),
                    format!("{}", arp_pkt.dest_addr),
                    display_macaddr(&arp_pkt.dest_mac))
            },
        });
        Some(Blue)
    }

    #[inline]
    fn format_compact_ipv4_unknown(&self, out: &mut String, ip_hdr: pktparse::ipv4::IPv4Header, data: &[u8]) -> Option<Colour> {
        out.push_str(&format!("[unknown] {:15} -> {:15} {:?}",
                        ip_hdr.source_addr,
                        ip_hdr.dest_addr,
                        data));
        None
    }

    #[inline]
    fn format_compact_ipv4_tcp(&self, out: &mut String, ip_hdr: pktparse::ipv4::IPv4Header, tcp_hdr: pktparse::tcp::TcpHeader, tcp: tcp::TCP) -> Option<Colour> {
        out.push_str(&format!("[tcp] {:22} -> {:22} ",
                        format!("{}:{}", ip_hdr.source_addr, tcp_hdr.source_port),
                        format!("{}:{}", ip_hdr.dest_addr, tcp_hdr.dest_port)));

        use structs::tcp::TCP::*;
        match tcp {
            HTTP(http) => {
                // println!("{}", Green.normal().paint(format!("\t\t\thttp: {:?} {:?}", format!("{} http://{}{} HTTP/{}", http.method, http.host.clone().unwrap_or("???".to_owned()), http.uri, http.version), http)));
                out.push_str(&format!("[http] {:?}", http)); // TODO
                Some(Green)
            },
            TLS(client_hello) => {
                let extra = display_kv_list(&[
                    ("hostname", client_hello.hostname),
                ]);

                out.push_str("[tls] ClientHello");
                out.push_str(&extra);
                Some(Green)
            },
            Text(text) => {
                out.push_str(&format!("[text] {:?}", text));
                Some(Red)
            },
            Binary(x) => {
                out.push_str(&format!("[binary] {:?}", x));
                Some(Red)
            },
        }
    }

    #[inline]
    fn format_compact_ipv4_udp(&self, out: &mut String, ip_hdr: pktparse::ipv4::IPv4Header, udp_hdr: pktparse::udp::UdpHeader, udp: udp::UDP) -> Option<Colour> {
        out.push_str(&format!("[udp] {:22} -> {:22} ",
                        format!("{}:{}", ip_hdr.source_addr, udp_hdr.source_port),
                        format!("{}:{}", ip_hdr.dest_addr, udp_hdr.dest_port)));

        use structs::udp::UDP::*;
        match udp {
            DHCP(dhcp) => {
                use structs::dhcp::DHCP::*;

                match dhcp {
                    DISCOVER(disc) => {
                        let extra = display_dhcp_kv_list(&[
                            ("hostname", disc.hostname),
                            ("requested_ip_address", disc.requested_ip_address),
                        ]);

                        out.push_str(&format!("[dhcp] DISCOVER: {}",
                                display_macadr_buf(disc.chaddr)));
                        out.push_str(&extra);
                    },
                    REQUEST(req) => {
                        let extra = display_dhcp_kv_list(&[
                            ("hostname", req.hostname),
                            ("requested_ip_address", req.requested_ip_address),
                        ]);

                        out.push_str(&format!("[dhcp] REQ: {}",
                                display_macadr_buf(req.chaddr)));
                        out.push_str(&extra);
                    },
                    ACK(ack) => {
                        let extra = display_dhcp_kv_list(&[
                            ("hostname", ack.hostname),
                            ("router", ack.router),
                            ("dns", ack.domain_name_server),
                        ]);

                        out.push_str(&format!("[dhcp] ACK: {} => {}",
                                display_macadr_buf(ack.chaddr),
                                ack.yiaddr));
                        out.push_str(&extra);
                    },
                    OFFER(offer) => {
                        let extra = display_dhcp_kv_list(&[
                            ("hostname", offer.hostname),
                            ("router", offer.router),
                            ("dns", offer.domain_name_server),
                        ]);

                        out.push_str(&format!("[dhcp] OFFER: {} => {}",
                                display_macadr_buf(offer.chaddr),
                                offer.yiaddr));
                        out.push_str(&extra);
                    },
                    _ => {
                        out.push_str(&format!("[dhcp] {:?}", dhcp)); // TODO
                    },
                };

                Some(Blue)
            },
            DNS(dns) => {
                use structs::dns::DNS::*;
                match dns {
                    Request(req) => {
                        out.push_str("[dns] req, ");

                        match req.questions.iter()
                            .map(|x| format!("{:?}", x))
                            .reduce(|a, b| a + &align(out.len(), &b))
                        {
                            Some(dns) => out.push_str(&dns),
                            None => out.push_str("[]"),
                        };
                    },
                    Response(resp) => {
                        out.push_str("[dns] resp, ");

                        match resp.answers.iter()
                            .map(|x| format!("{:?}", x))
                            .reduce(|a, b| a + &align(out.len(), &b))
                        {
                            Some(dns) => out.push_str(&dns),
                            None => out.push_str("[]"),
                        };
                    },
                };

                Some(Yellow)
            },
            SSDP(ssdp) => {
                use structs::ssdp::SSDP::*;
                out.push_str(&match ssdp {
                    Discover(None) => format!("[ssdp] searching..."),
                    Discover(Some(extra)) => format!("[ssdp] searching({:?})...", extra),
                    Notify(extra) => format!("[ssdp] notify: {:?}", extra),
                    BTSearch(extra) => format!("[ssdp] torrent search: {:?}", extra),
                });
                Some(Purple)
            },
            Text(text) => {
                out.push_str(&format!("[text] {:?}", text));
                Some(Red)
            },
            Binary(x) => {
                out.push_str(&format!("[binary] {:?}", x));
                Some(Red)
            },
        }
    }

    #[inline]
    fn print_detailed(&self, packet: Raw) {
        use structs::raw::Raw::Unknown;
        match packet {
            Ether(eth_frame, eth) => {
                println!("eth: {:?}", eth_frame);
                self.print_detailed_eth(1, eth);
            },
            Tun(eth) => self.print_detailed_eth(0, eth),
            Unknown(data) => println!("unknown: {:?}", data),
        }
    }

    #[inline]
    fn print_detailed_eth(&self, indent: usize, eth: ether::Ether) {
        match eth {
            Arp(arp_pkt) => {
                println!("{}{}", "\t".repeat(indent), self.colorify(Blue, format!("arp: {:?}", arp_pkt)));
            },
            IPv4(ip_hdr, TCP(tcp_hdr, tcp)) => {
                println!("{}ipv4: {:?}", "\t".repeat(indent), ip_hdr);
                println!("{}tcp: {:?}",  "\t".repeat(indent+1), tcp_hdr);
                println!("{}{}",         "\t".repeat(indent+2), self.print_detailed_tcp(tcp));
            },
            IPv4(ip_hdr, UDP(udp_hdr, udp)) => {
                println!("{}ipv4: {:?}", "\t".repeat(indent), ip_hdr);
                println!("{}udp: {:?}",  "\t".repeat(indent+1), udp_hdr);
                println!("{}{}",         "\t".repeat(indent+2), self.print_detailed_udp(udp));
            },
            IPv4(ip_hdr, ipv4::IPv4::Unknown(data)) => {
                println!("{}ipv4: {:?}",     "\t".repeat(indent), ip_hdr);
                println!("{}unknown: {:?}",  "\t".repeat(indent+1), data);
            },
            ether::Ether::Unknown(data) => {
                println!("{}unknown: {:?}", "\t".repeat(indent), data);
            }
        }
    }

    #[inline]
    fn print_detailed_tcp(&self, tcp: tcp::TCP) -> String {
        use structs::tcp::TCP::*;
        match tcp {
            HTTP(http) => {
                self.colorify(Green, format!("http: {:?} {:?}", format!("{} http://{}{} HTTP/{}", http.method, http.host.clone().unwrap_or_else(|| "???".to_string()), http.uri, http.version), http))
            },
            TLS(client_hello) => {
                self.colorify(Green, format!("tls: {:?}", client_hello))
            },
            Text(text) => {
                self.colorify(Blue, format!("remaining: {:?}", text))
            },
            Binary(x) => {
                self.colorify(Yellow, format!("remaining: {:?}", x))
            },
        }
    }

    #[inline]
    fn print_detailed_udp(&self, udp: udp::UDP) -> String {
        use structs::udp::UDP::*;
        match udp {
            DHCP(dhcp) => {
                self.colorify(Green, format!("dhcp: {:?}", dhcp))
            },
            DNS(dns) => {
                self.colorify(Green, format!("dns: {:?}", dns))
            },
            SSDP(ssdp) => {
                self.colorify(Purple, format!("ssdp: {:?}", ssdp))
            },
            Text(text) => {
                self.colorify(Blue, format!("remaining: {:?}", text))
            },
            Binary(x) => {
                self.colorify(Yellow, format!("remaining: {:?}", x))
            },
        }
    }

    #[inline]
    fn print_json(&self, packet: &Raw) {
        println!("{}", serde_json::to_string(packet).unwrap());
    }
}

pub struct Filter {
    verbose: u64,
}

impl Filter {
    pub fn new(verbose: u64) -> Filter {
        Filter {
            verbose,
        }
    }

    #[inline]
    pub fn matches(&self, packet: &Raw) -> bool {
        packet.noise_level().to_u64() <= self.verbose
    }
}

#[inline]
fn align(len: usize, a: &str) -> String {
    format!("\n{}{}", " ".repeat(len), &a)
}

// TODO: upstream
#[inline]
fn display_macaddr(mac: &pktparse::ethernet::MacAddress) -> String {
    display_macadr_buf(mac.0)
}

#[inline]
fn display_macadr_buf(mac: [u8; 6]) -> String {
    let mut string = mac.iter()
                        .fold(String::new(), |acc, &x| {
                            format!("{}{:02x}:", acc, x)
                        });
    string.pop();
    string
}

#[inline]
fn display_kv_list(list: &[(&str, Option<String>)]) -> String {
    list.into_iter()
        .filter_map(|&(key, ref value)| {
            value.as_ref().map(|value| {
                format!("{}: {:?}", key, value)
            })
        })
        .reduce(|a, b| a + ", " + &b)
        .map(|extra| format!(" ({})", extra))
        .unwrap_or_else(|| String::new())
}

#[inline]
fn display_dhcp_kv_list(list: &[(&str, Option<DhcpOption>)]) -> String {
    list.into_iter()
        .filter_map(|&(key, ref value)| {
            value.as_ref().map(|value| {
                let value = match *value {
                    DhcpOption::String(ref value) => format!("{:?}", value),
                    DhcpOption::IPv4(ref value) => format!("{:?}", value),
                    DhcpOption::Bytes(ref value) => format!("{:?}", value),
                };

                format!("{}: {}", key, value)
            })
        })
        .reduce(|a, b| a + ", " + &b)
        .map(|extra| format!(" ({})", extra))
        .unwrap_or_else(|| String::new())
}

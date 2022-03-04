use std::sync::Arc;

use ansi_term::Color::{self, Yellow, Blue, Green, Red, Purple, Fixed};
use bstr::ByteSlice;
use reduce::Reduce;
use sha2::{Sha512, Digest};
use std::cmp;
use std::fmt::Debug;
use pktparse::icmp::{IcmpHeader, IcmpCode, IcmpData};

use crate::structs::ether;
use crate::structs::arp;
use crate::structs::cjdns;
use crate::structs::ip::IPHeader;
use crate::structs::ipv4;
use crate::structs::ipv6;
use crate::structs::tcp;
use crate::structs::udp;
use crate::structs::icmp;
use crate::structs::tls;
use crate::structs::raw::Raw;
use crate::structs::prelude::*;
use crate::structs::NoiseLevel;

const GREY: u8 = 245;


pub struct Config {
    fmt: Format,
    filter: Arc<Filter>,
}

impl Config {
    pub fn new(layout: Layout, verbosity: u8, colors: bool) -> Config {
        Config {
            fmt: Format::new(layout, colors),
            filter: Arc::new(Filter::new(verbosity)),
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
    Debugging,
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
            Layout::Debugging => self.print_debugging(packet),
            Layout::Json => self.print_json(&packet),
        }
    }

    #[inline]
    fn colorify(&self, color: Color, out: String) -> String {
        if self.colors {
            color.normal().paint(out).to_string()
        } else {
            out
        }
    }

    #[inline]
    fn print_compact(&self, packet: Raw) {
        let mut out = String::new();

        use crate::structs::raw::Raw::Unknown;
        let color = match packet {
            Ether(eth_frame, eth) => {
                out += &format!("{} -> {}, ",
                                display_macaddr(eth_frame.source_mac),
                                display_macaddr(eth_frame.dest_mac));

                self.format_compact_eth(&mut out, eth)
            },
            Tun(eth) => self.format_compact_eth(&mut out, eth),
            Sll(eth) => self.format_compact_eth(&mut out, eth),
            Unknown(data) => self.format_compact_unknown_data(&mut out, &data),
        };

        println!("{}", match color {
            Some(color) => self.colorify(color, out),
            None => out,
        });
    }

    #[inline]
    fn format_compact_unknown_data(&self, out: &mut String, data: &[u8]) -> Option<Color> {
        out.push_str(&format!("[unknown] {:?}", data));
        None
    }

    #[inline]
    fn format_compact_eth(&self, out: &mut String, eth: ether::Ether) -> Option<Color> {
        match eth {
            Arp(arp_pkt) => Some(self.format_compact_arp(out, &arp_pkt)),
            IPv4(ip_hdr, ipv4) => self.format_compact_ipv4(out, &ip_hdr, ipv4),
            IPv6(ip_hdr, ipv6) => self.format_compact_ipv6(out, &ip_hdr, ipv6),
            Cjdns(cjdns_pkt) => Some(self.format_compact_cjdns(out, &cjdns_pkt)),
            ether::Ether::Unknown(data) => self.format_compact_unknown_data(out, &data),
        }
    }

    #[inline]
    fn format_compact_arp(&self, out: &mut String, arp_pkt: &arp::ARP) -> Color {
        use crate::structs::arp::ARP;
        out.push_str(&match arp_pkt {
            ARP::Request(arp_pkt) => {
                format!("[arp/request] {:15}   ?                         (tell {}, {})",
                    arp_pkt.dest_addr.to_string(),
                    arp_pkt.src_addr,
                    display_macaddr(arp_pkt.src_mac))
            },
            ARP::Reply(arp_pkt) => {
                format!("[arp/reply  ] {:15}   ! => {}    (fyi  {}, {})",
                    arp_pkt.src_addr.to_string(),
                    display_macaddr(arp_pkt.src_mac),
                    arp_pkt.dest_addr,
                    display_macaddr(arp_pkt.dest_mac))
            },
        });
        Blue
    }

    #[inline]
    fn format_compact_cjdns(&self, out: &mut String, cjdns: &cjdns::CjdnsEthPkt) -> Color {
        let password = cjdns.password.iter()
            .map(|b| {
                format!("\\x{:02x}", b)
            })
            .fold(String::new(), |a, b| a + &b);

        let ipv6 = {
            let bytes1 = Sha512::digest(&cjdns.pubkey);
            let bytes2 = Sha512::digest(&bytes1);

            let mut iter = bytes2.as_slice().iter();

            let mut ipv6 = String::new();
            for x in 0..8 {
                let b1 = iter.next().unwrap();
                let b2 = iter.next().unwrap();

                ipv6.push_str(&format!("{:02x}{:02x}", b1, b2));

                if x != 7 {
                    ipv6.push(':');
                }
            }

            ipv6
        };

        out.push_str(&format!("[cjdns beacon] version={:?}, password=\"{}\", ipv6={:?}, pubkey={:?}",
                              cjdns.version,
                              password,
                              ipv6,
                              cjdns.pubkey));

        Purple
    }

    #[inline]
    fn format_compact_ipv4<IP: IPHeader>(&self, out: &mut String, ip_hdr: &IP, next: ipv4::IPv4) -> Option<Color> {
        match next {
            ipv4::IPv4::TCP(tcp_hdr, tcp) => Some(self.format_compact_ip_tcp(out, ip_hdr, &tcp_hdr, tcp)),
            ipv4::IPv4::UDP(udp_hdr, udp) => Some(self.format_compact_ip_udp(out, ip_hdr, udp_hdr, udp)),
            ipv4::IPv4::ICMP(icmp_hdr, icmp) => Some(self.format_compact_ip_icmp(out, ip_hdr, icmp_hdr, icmp)),
            ipv4::IPv4::Unknown(data) => self.format_compact_ip_unknown(out, ip_hdr, &data),
        }
    }

    #[inline]
    fn format_compact_ipv6<IP: IPHeader>(&self, out: &mut String, ip_hdr: &IP, next: ipv6::IPv6) -> Option<Color> {
        match next {
            ipv6::IPv6::TCP(tcp_hdr, tcp) => Some(self.format_compact_ip_tcp(out, ip_hdr, &tcp_hdr, tcp)),
            ipv6::IPv6::UDP(udp_hdr, udp) => Some(self.format_compact_ip_udp(out, ip_hdr, udp_hdr, udp)),
            ipv6::IPv6::Unknown(data) => self.format_compact_ip_unknown(out, ip_hdr, &data),
        }
    }

    #[inline]
    fn format_compact_ip_unknown<IP: IPHeader>(&self, out: &mut String, ip_hdr: &IP, data: &[u8]) -> Option<Color> {
        out.push_str(&format!("[unknown] {} -> {} {:?}",
                        ip_hdr.source_addr(),
                        ip_hdr.dest_addr(),
                        data));
        None
    }

    #[inline]
    fn format_compact_ip_tcp<IP: IPHeader>(&self, out: &mut String, ip_hdr: &IP, tcp_hdr: &pktparse::tcp::TcpHeader, tcp: tcp::TCP) -> Color {
        let mut flags = String::new();
        if tcp_hdr.flag_syn { flags.push('S') }
        if tcp_hdr.flag_ack { flags.push('A') }
        if tcp_hdr.flag_rst { flags.push('R') }
        if tcp_hdr.flag_fin { flags.push('F') }

        out.push_str(&format!("[tcp/{:2}] {:22} -> {:22} ", flags,
                        format!("{}:{}", ip_hdr.source_addr(), tcp_hdr.source_port),
                        format!("{}:{}", ip_hdr.dest_addr(), tcp_hdr.dest_port)));

        use crate::structs::tcp::TCP::*;
        match tcp {
            HTTP(http) => {
                // println!("{}", Green.normal().paint(format!("\t\t\thttp: {:?} {:?}", format!("{} http://{}{} HTTP/{}", http.method, http.host.clone().unwrap_or("???".to_owned()), http.uri, http.version), http)));
                out.push_str(&format!("[http] {:?}", http)); // TODO
                Green
            },
            TLS(tls::TLS::ClientHello(client_hello)) => {
                let extra = display_kv_list(&[
                    ("version", client_hello.version),
                    ("session", client_hello.session_id.as_deref()),
                    ("hostname", client_hello.hostname.as_deref()),
                ]);

                out.push_str("[tls] ClientHello");
                out.push_str(&extra);
                Green
            },
            TLS(tls::TLS::ServerHello(server_hello)) => {
                let extra = display_kv_list(&[
                    ("version", server_hello.version),
                    ("session", server_hello.session_id.as_deref()),
                    ("cipher", server_hello.cipher),
                ]);

                out.push_str("[tls] ServerHello");
                out.push_str(&extra);
                Green
            },
            Text(text) => {
                out.push_str(&format!("[text] {:?}", text));
                Red
            },
            Binary(x) => {
                out.push_str(&format!("[binary] {:?}", x.as_bstr()));
                Red
            },
            Empty => {
                Fixed(GREY)
            },
        }
    }

    #[inline]
    fn format_compact_ip_udp<IP: IPHeader>(&self, out: &mut String, ip_hdr: &IP, udp_hdr: pktparse::udp::UdpHeader, udp: udp::UDP) -> Color {
        out.push_str(&format!("[udp   ] {:22} -> {:22} ",
                        format!("{}:{}", ip_hdr.source_addr(), udp_hdr.source_port),
                        format!("{}:{}", ip_hdr.dest_addr(), udp_hdr.dest_port)));

        use crate::structs::udp::UDP::*;
        match udp {
            DHCP(dhcp) => {
                use crate::structs::dhcp::DHCP::*;

                match dhcp {
                    DISCOVER(disc) => {
                        out.push_str(&format!("[dhcp] DISCOVER: {}",
                                display_macadr_buf(disc.chaddr)));
                        out.push_str(&DhcpKvListWriter::new()
                                     .append("hostname", &disc.hostname)
                                     .append("requested_ip_address", &disc.requested_ip_address)
                                     .finalize());
                    },
                    REQUEST(req) => {
                        out.push_str(&format!("[dhcp] REQ: {}",
                                display_macadr_buf(req.chaddr)));
                        out.push_str(&DhcpKvListWriter::new()
                                     .append("hostname", &req.hostname)
                                     .append("requested_ip_address", &req.requested_ip_address)
                                     .finalize());
                    },
                    ACK(ack) => {
                        out.push_str(&format!("[dhcp] ACK: {} => {}",
                                display_macadr_buf(ack.chaddr),
                                ack.yiaddr));
                        out.push_str(&DhcpKvListWriter::new()
                                     .append("hostname", &ack.hostname)
                                     .append("router", &ack.router)
                                     .append("dns", &ack.domain_name_server)
                                     .finalize());
                    },
                    OFFER(offer) => {
                        out.push_str(&format!("[dhcp] OFFER: {} => {}",
                                display_macadr_buf(offer.chaddr),
                                offer.yiaddr));
                        out.push_str(&DhcpKvListWriter::new()
                                     .append("hostname", &offer.hostname)
                                     .append("router", &offer.router)
                                     .append("dns", &offer.domain_name_server)
                                     .finalize());
                    },
                    _ => {
                        out.push_str(&format!("[dhcp] {:?}", dhcp)); // TODO
                    },
                };

                Blue
            },
            DNS(dns) => {
                use crate::structs::dns::DNS::*;
                match dns {
                    Request(req) => {
                        out.push_str("[dns] req, ");

                        match Reduce::reduce(req.questions.iter()
                            .map(|x| format!("{:?}", x)), |a, b| a + &align(out.len(), &b))
                        {
                            Some(dns) => out.push_str(&dns),
                            None => out.push_str("[]"),
                        };
                    },
                    Response(resp) => {
                        out.push_str("[dns] resp, ");

                        match Reduce::reduce(resp.answers.iter()
                            .map(|x| format!("{:?}", x)), |a, b| a + &align(out.len(), &b))
                        {
                            Some(dns) => out.push_str(&dns),
                            None => out.push_str("[]"),
                        };
                    },
                };

                Yellow
            },
            SSDP(ssdp) => {
                use crate::structs::ssdp::SSDP::*;
                out.push_str(&match ssdp {
                    Discover(None) => "[ssdp] searching...".to_string(),
                    Discover(Some(extra)) => format!("[ssdp] searching({:?})...", extra),
                    Notify(extra) => format!("[ssdp] notify: {:?}", extra),
                    BTSearch(extra) => format!("[ssdp] torrent search: {:?}", extra),
                });
                Purple
            },
            Dropbox(dropbox) => {
                out.push_str(&format!("[dropbox] beacon: version={:?}, \
                                                         host_int={:?}, \
                                                         namespaces={:?}, \
                                                         displayname={:?}, \
                                                         port={:?}",
                                        dropbox.version,
                                        dropbox.host_int,
                                        dropbox.namespaces,
                                        dropbox.displayname,
                                        dropbox.port));
                Purple
            },
            Text(text) => {
                out.push_str(&format!("[text] {:?}", text));
                Red
            },
            Binary(x) => {
                out.push_str(&format!("[binary] {:?}", x.as_bstr()));
                Red
            },
        }
    }

    fn format_compact_ip_icmp<IP: IPHeader>(&self, out: &mut String, ip_hdr: &IP, icmp_hdr: IcmpHeader, icmp: icmp::ICMP) -> Color {
        let code = match icmp_hdr.code {
            IcmpCode::EchoReply => Some("icmp/pong"),
            /*
            IcmpCode::Reserved,
            */
            IcmpCode::DestinationUnreachable(_) => Some("icmp/unrch"),
            /*
            IcmpCode::DestinationUnreachable(Unreachable),
            IcmpCode::SourceQuench,
            IcmpCode::Redirect(Redirect),
            */
            IcmpCode::EchoRequest => Some("icmp/ping"),
            /*
            IcmpCode::RouterAdvertisment,
            IcmpCode::RouterSolicication,
            */
            IcmpCode::TimeExceeded(_) => Some("icmp/ttl"),
            /*
            IcmpCode::ParameterProblem(ParameterProblem),
            IcmpCode::Timestamp,
            IcmpCode::TimestampReply,
            IcmpCode::ExtendedEchoRequest,
            IcmpCode::ExtendedEchoReply(ExtendedEchoReply),
            IcmpCode::Other(u16)
            */
            _ => None,
        };
        out.push_str(&format!("[{:10}] {:18} -> {:22} [code={:?}",
                        code.unwrap_or("icmp"),
                        ip_hdr.source_addr(),
                        ip_hdr.dest_addr(),
                        icmp_hdr.code));

        if icmp_hdr.data != IcmpData::None {
            out.push_str(&format!(", data={:?}", icmp_hdr.data));
        }

        out.push_str(&format!("] {:?}", icmp.data.as_bstr()));

        Blue
    }

    #[inline]
    fn print_debugging(&self, packet: Raw) {
        use crate::structs::raw::Raw::Unknown;
        match packet {
            Ether(eth_frame, eth) => {
                println!("eth: {:?}", eth_frame);
                self.print_debugging_eth(1, eth);
            },
            Tun(eth) => self.print_debugging_eth(0, eth),
            Sll(eth) => self.print_debugging_eth(0, eth),
            Unknown(data) => println!("unknown: {:?}", data),
        }
    }

    #[inline]
    fn print_debugging_eth(&self, indent: usize, eth: ether::Ether) {
        match eth {
            Arp(arp_pkt) => {
                println!("{}{}", "\t".repeat(indent), self.colorify(Blue, format!("arp: {:?}", arp_pkt)));
            },
            IPv4(ip_hdr, ipv4::IPv4::TCP(tcp_hdr, tcp)) => {
                println!("{}ipv4: {:?}", "\t".repeat(indent), ip_hdr);
                println!("{}tcp: {:?}",  "\t".repeat(indent+1), tcp_hdr);
                println!("{}{}",         "\t".repeat(indent+2), self.print_debugging_tcp(tcp));
            },
            IPv4(ip_hdr, ipv4::IPv4::UDP(udp_hdr, udp)) => {
                println!("{}ipv4: {:?}", "\t".repeat(indent), ip_hdr);
                println!("{}udp: {:?}",  "\t".repeat(indent+1), udp_hdr);
                println!("{}{}",         "\t".repeat(indent+2), self.print_debugging_udp(udp));
            },
            IPv4(ip_hdr, ipv4::IPv4::ICMP(icmp_hdr, icmp)) => {
                println!("{}ipv4: {:?}", "\t".repeat(indent), ip_hdr);
                println!("{}icmp: {:?}",  "\t".repeat(indent+1), icmp_hdr);
                println!("{}{:?}",         "\t".repeat(indent+2), icmp.data);
            },
            IPv4(ip_hdr, ipv4::IPv4::Unknown(data)) => {
                println!("{}ipv4: {:?}",     "\t".repeat(indent), ip_hdr);
                println!("{}unknown: {:?}",  "\t".repeat(indent+1), data);
            },
            IPv6(ip_hdr, ipv6::IPv6::TCP(tcp_hdr, tcp)) => {
                println!("{}ipv6: {:?}", "\t".repeat(indent), ip_hdr);
                println!("{}tcp: {:?}",  "\t".repeat(indent+1), tcp_hdr);
                println!("{}{}",         "\t".repeat(indent+2), self.print_debugging_tcp(tcp));
            },
            IPv6(ip_hdr, ipv6::IPv6::UDP(udp_hdr, udp)) => {
                println!("{}ipv6: {:?}", "\t".repeat(indent), ip_hdr);
                println!("{}udp: {:?}",  "\t".repeat(indent+1), udp_hdr);
                println!("{}{}",         "\t".repeat(indent+2), self.print_debugging_udp(udp));
            },
            IPv6(ip_hdr, ipv6::IPv6::Unknown(data)) => {
                println!("{}ipv6: {:?}",     "\t".repeat(indent), ip_hdr);
                println!("{}unknown: {:?}",  "\t".repeat(indent+1), data);
            },
            Cjdns(cjdns_pkt) => {
                println!("{}cjdns: {:?}",     "\t".repeat(indent), cjdns_pkt);
            },
            ether::Ether::Unknown(data) => {
                println!("{}unknown: {:?}", "\t".repeat(indent), data);
            }
        }
    }

    #[inline]
    fn print_debugging_tcp(&self, tcp: tcp::TCP) -> String {
        use crate::structs::tcp::TCP::*;
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
            Empty => self.colorify(Fixed(GREY), String::new()),
        }
    }

    #[inline]
    fn print_debugging_udp(&self, udp: udp::UDP) -> String {
        use crate::structs::udp::UDP::*;
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
            Dropbox(dropbox) => {
                self.colorify(Purple, format!("dropbox: {:?}", dropbox))
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
    pub verbosity: u8,
}

impl Filter {
    #[inline]
    pub fn new(verbosity: u8) -> Filter {
        let verbosity = cmp::min(verbosity, NoiseLevel::Maximum.into_u8());
        Filter {
            verbosity,
        }
    }

    #[inline]
    pub fn matches(&self, packet: &Raw) -> bool {
        packet.noise_level().into_u8() <= self.verbosity
    }
}

#[inline]
fn align(len: usize, a: &str) -> String {
    format!("\n{}{}", " ".repeat(len), &a)
}

// TODO: upstream
#[inline]
fn display_macaddr(mac: pktparse::ethernet::MacAddress) -> String {
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
fn display_kv_list(list: &[(&str, Option<&str>)]) -> String {
    Reduce::reduce(list.iter()
        .filter_map(|&(key, ref value)| {
            value.as_ref().map(|value| {
                format!("{}: {:?}", key, value)
            })
        }), |a, b| a + ", " + &b)
        .map_or_else(String::new, |extra| format!(" ({})", extra))
}

struct DhcpKvListWriter<'a> {
    elements: Vec<(&'a str, String)>,
}

impl<'a> DhcpKvListWriter<'a> {
    fn new() -> DhcpKvListWriter<'a> {
        DhcpKvListWriter{
            elements: vec!()
        }
    }

    fn append<T: Debug>(mut self, key: &'a str, value: &Option<T>) -> Self {
        if let Some(value) = value {
            self.elements.push((
                key,
                format!("{:?}", value),
            ));
        }
        self
    }

    fn finalize(self) -> String {
        Reduce::reduce(self.elements.iter()
            .map(|&(key, ref value)| {
                format!("{}: {}", key, value)
            }), |a, b| a + ", " + &b)
            .map_or_else(String::new, |extra| format!(" ({})", extra))
    }
}

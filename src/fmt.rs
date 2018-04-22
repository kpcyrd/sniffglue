use std::sync::Arc;

use pktparse;
use reduce::Reduce;
use ansi_term::Colour::{self, Yellow, Blue, Green, Red};
use serde_json;

use structs::raw::Raw;
use structs::prelude::*;
use structs::dhcp::DhcpOption;


pub struct Config {
    fmt: Format,
    filter: Arc<Filter>,
}

impl Config {
    pub fn new(layout: Layout, log_noise: bool, colors: bool) -> Config {
        Config {
            fmt: Format::new(layout, colors),
            filter: Arc::new(Filter::new(log_noise)),
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

        let color = match packet {
            Ether(eth_frame, eth) => {
                out += &format!("{} -> {}",
                                display_macaddr(&eth_frame.source_mac),
                                display_macaddr(&eth_frame.dest_mac));

                match eth {
                    Arp(arp_pkt) => {
                        use structs::arp::ARP;
                        match arp_pkt {
                            ARP::Request(arp_pkt) => {
                                out += &format!(", [arp/request] who has {:15}? (tell {}, {})",
                                    format!("{}", arp_pkt.dest_addr),
                                    format!("{}", arp_pkt.src_addr),
                                    display_macaddr(&arp_pkt.src_mac));
                            },
                            ARP::Reply(arp_pkt) => {
                                out += &format!(", [arp/reply] {:15} => {} (fyi {}, {})",
                                    format!("{}", arp_pkt.src_addr),
                                    display_macaddr(&arp_pkt.src_mac),
                                    format!("{}", arp_pkt.dest_addr),
                                    display_macaddr(&arp_pkt.dest_mac));
                            },
                        }
                        Some(Blue)
                    },
                    IPv4(ip_hdr, TCP(tcp_hdr, tcp)) => {
                        out += &format!(", [tcp] {:22} -> {:22} ",
                                        format!("{}:{}", ip_hdr.source_addr, tcp_hdr.source_port),
                                        format!("{}:{}", ip_hdr.dest_addr, tcp_hdr.dest_port));

                        use structs::tcp::TCP::*;
                        match tcp {
                            HTTP(http) => {
                                // println!("{}", Green.normal().paint(format!("\t\t\thttp: {:?} {:?}", format!("{} http://{}{} HTTP/{}", http.method, http.host.clone().unwrap_or("???".to_owned()), http.uri, http.version), http)));
                                out += &format!("[http] {:?}", http); // TODO
                                Some(Green)
                            },
                            TLS(client_hello) => {
                                let extra = display_kv_list(&[
                                    ("hostname", client_hello.hostname),
                                ]);

                                out += "[tls] ClientHello";
                                out += &extra;
                                Some(Green)
                            },
                            Text(text) => {
                                out += &format!("[text] {:?}", text);
                                Some(Red)
                            },
                            Binary(x) => {
                                out += &format!("[binary] {:?}", x);
                                Some(Red)
                            },
                        }
                    },
                    IPv4(ip_hdr, UDP(udp_hdr, udp)) => {
                        out += &format!(", [udp] {:22} -> {:22} ",
                                        format!("{}:{}", ip_hdr.source_addr, udp_hdr.source_port),
                                        format!("{}:{}", ip_hdr.dest_addr, udp_hdr.dest_port));

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

                                        out += &(format!("[dhcp] DISCOVER: {}",
                                                display_macadr_buf(disc.chaddr)) + &extra);
                                    },
                                    REQUEST(req) => {
                                        let extra = display_dhcp_kv_list(&[
                                            ("hostname", req.hostname),
                                            ("requested_ip_address", req.requested_ip_address),
                                        ]);

                                        out += &(format!("[dhcp] REQ: {}",
                                                display_macadr_buf(req.chaddr)) + &extra);
                                    },
                                    ACK(ack) => {
                                        let extra = display_dhcp_kv_list(&[
                                            ("hostname", ack.hostname),
                                            ("router", ack.router),
                                            ("dns", ack.domain_name_server),
                                        ]);

                                        out += &(format!("[dhcp] ACK: {} => {}",
                                                display_macadr_buf(ack.chaddr),
                                                ack.yiaddr) + &extra);
                                    },
                                    OFFER(offer) => {
                                        let extra = display_dhcp_kv_list(&[
                                            ("hostname", offer.hostname),
                                            ("router", offer.router),
                                            ("dns", offer.domain_name_server),
                                        ]);

                                        out += &(format!("[dhcp] OFFER: {} => {}",
                                                display_macadr_buf(offer.chaddr),
                                                offer.yiaddr) + &extra);
                                    },
                                    _ => {
                                        out += &format!("[dhcp] {:?}", dhcp); // TODO
                                    },
                                };

                                Some(Blue)
                            },
                            DNS(dns) => {
                                use structs::dns::DNS::*;
                                match dns {
                                    Request(req) => {
                                        out += "[dns] req, ";

                                        match req.questions.iter()
                                            .map(|x| format!("{:?}", x))
                                            .reduce(|a, b| a + &align(out.len(), &b))
                                        {
                                            Some(dns) => out += &dns,
                                            None => out += "[]",
                                        };
                                    },
                                    Response(resp) => {
                                        out += "[dns] resp, ";

                                        match resp.answers.iter()
                                            .map(|x| format!("{:?}", x))
                                            .reduce(|a, b| a + &align(out.len(), &b))
                                        {
                                            Some(dns) => out += &dns,
                                            None => out += "[]",
                                        };
                                    },
                                };

                                Some(Yellow)
                            },
                            Text(text) => {
                                out += &format!("[text] {:?}", text);
                                Some(Red)
                            },
                            Binary(x) => {
                                out += &format!("[binary] {:?}", x);
                                Some(Red)
                            },
                        }
                    },
                }
            },
        };

        println!("{}", match color {
            Some(color) => self.colorify(color, out),
            None => out,
        });
    }

    #[inline]
    fn print_detailed(&self, packet: Raw) {
        match packet {
            Ether(eth_frame, eth) => {
                println!("eth: {:?}", eth_frame);

                match eth {
                    Arp(arp_pkt) => {
                        self.colorify(Blue, format!("\tarp: {:?}", arp_pkt));
                    },
                    IPv4(ip_hdr, TCP(tcp_hdr, tcp)) => {
                        println!("\tipv4: {:?}", ip_hdr);
                        println!("\t\ttcp: {:?}", tcp_hdr);

                        use structs::tcp::TCP::*;
                        println!("\t\t\t{}", match tcp {
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
                        });
                    },
                    IPv4(ip_hdr, UDP(udp_hdr, udp)) => {
                        println!("\tipv4: {:?}", ip_hdr);
                        println!("\t\tudp: {:?}", udp_hdr);

                        use structs::udp::UDP::*;
                        println!("\t\t\t{}", match udp {
                            DHCP(dhcp) => {
                                self.colorify(Green, format!("dhcp: {:?}", dhcp))
                            },
                            DNS(dns) => {
                                self.colorify(Green, format!("dns: {:?}", dns))
                            },
                            Text(text) => {
                                self.colorify(Blue, format!("remaining: {:?}", text))
                            },
                            Binary(x) => {
                                self.colorify(Yellow, format!("remaining: {:?}", x))
                            },
                        });
                    },
                }
            },
        }
    }

    #[inline]
    fn print_json(&self, packet: &Raw) {
        println!("{}", serde_json::to_string(packet).unwrap());
    }
}

pub struct Filter {
    log_noise: bool,
}

impl Filter {
    pub fn new(log_noise: bool) -> Filter {
        Filter {
            log_noise,
        }
    }

    #[inline]
    pub fn matches(&self, packet: &Raw) -> bool {
        if self.log_noise {
            true
        } else {
            !packet.is_noise()
        }
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
    match list.into_iter()
        .filter_map(|&(key, ref value)| {
            match *value {
                Some(ref value) => {
                    Some(format!("{}: {:?}", key, value))
                },
                None => None,
            }
        })
        .reduce(|a, b| a + ", " + &b)
    {
        Some(extra) => format!(" ({})", extra),
        None => String::new(),
    }
}

#[inline]
fn display_dhcp_kv_list(list: &[(&str, Option<DhcpOption>)]) -> String {
    match list.into_iter()
        .filter_map(|&(key, ref value)| {
            match *value {
                Some(ref value) => {
                    let value = match *value {
                        DhcpOption::String(ref value) => format!("{:?}", value),
                        DhcpOption::IPv4(ref value) => format!("{:?}", value),
                        DhcpOption::Bytes(ref value) => format!("{:?}", value),
                    };

                    Some(format!("{}: {}", key, value))
                },
                None => None,
            }
        })
        .reduce(|a, b| a + ", " + &b)
    {
        Some(extra) => format!(" ({})", extra),
        None => String::new(),
    }
}

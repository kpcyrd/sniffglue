use std::sync::Arc;

use pktparse;
use reduce::Reduce;
use ansi_term::Colour::{Yellow, Blue, Green};

use structs::raw::Raw;
use structs::prelude::*;


pub struct Config {
    fmt: Format,
    filter: Arc<Filter>,
}

impl Config {
    pub fn new(layout: Layout, log_noise: bool) -> Config {
        Config {
            fmt: Format::new(layout),
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
}

pub struct Format {
    layout: Layout,
}

impl Format {
    pub fn new(layout: Layout) -> Format {
        Format {
            layout,
        }
    }

    #[inline]
    pub fn print(&self, packet: Raw) {
        match self.layout {
            Layout::Compact => self.print_compact(packet),
            Layout::Detailed => self.print_detailed(packet),
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
                                out += &format!("[tls] {:?}", client_hello.hostname);
                                Some(Green)
                            },
                            Text(text) => {
                                out += &format!("[text] {:?}", text);
                                Some(Blue)
                            },
                            Binary(x) => {
                                out += &format!("[binary] {:?}", x);
                                Some(Blue)
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
                                out += &format!("[dhcp] {:?}", dhcp); // TODO
                                None
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
                                Some(Blue)
                            },
                            Binary(x) => {
                                out += &format!("[binary] {:?}", x);
                                Some(Blue)
                            },
                        }
                    },
                }
            },
        };

        println!("{}", match color {
            Some(color) => color.normal().paint(out).to_string(),
            None => out,
        });
    }

    #[inline]
    fn print_detailed(&self, packet: Raw) {
        match packet {
            Ether(eth_frame, eth) => {
                println!("eth: {:?}", eth_frame);

                match eth {
                    IPv4(ip_hdr, TCP(tcp_hdr, tcp)) => {
                        println!("\tipv4: {:?}", ip_hdr);
                        println!("\t\ttcp: {:?}", tcp_hdr);

                        use structs::tcp::TCP::*;
                        match tcp {
                            HTTP(http) => {
                                println!("{}", Green.normal().paint(format!("\t\t\thttp: {:?} {:?}", format!("{} http://{}{} HTTP/{}", http.method, http.host.clone().unwrap_or("???".to_owned()), http.uri, http.version), http)));
                            },
                            TLS(client_hello) => {
                                println!("{}", Green.normal().paint(format!("\t\t\ttls: {:?}", client_hello)));
                            },
                            Text(text) => {
                                println!("{}", Blue.normal().paint(format!("\t\t\tremaining: {:?}", text)));
                            },
                            Binary(x) => {
                                println!("{}", Yellow.normal().paint(format!("\t\t\tremaining: {:?}", x)));
                            },
                        }
                    },
                    IPv4(ip_hdr, UDP(udp_hdr, udp)) => {
                        println!("\tipv4: {:?}", ip_hdr);
                        println!("\t\tudp: {:?}", udp_hdr);

                        use structs::udp::UDP::*;
                        match udp {
                            DHCP(dhcp) => {
                                println!("{}", Green.normal().paint(format!("\t\t\tdhcp: {:?}", dhcp)));
                            },
                            DNS(dns) => {
                                println!("{}", Green.normal().paint(format!("\t\t\tdns: {:?}", dns)));
                            },
                            Text(text) => {
                                println!("{}", Blue.normal().paint(format!("\t\t\tremaining: {:?}", text)));
                            },
                            Binary(x) => {
                                println!("{}", Yellow.normal().paint(format!("\t\t\tremaining: {:?}", x)));
                            },
                        }
                    },
                }
            },
        }
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
fn display_macaddr(mac: &pktparse::ethernet::MacAddress) -> String {
    let mut string = mac.0.iter()
                        .fold(String::new(), |acc, &x| {
                            format!("{}{:02x}:", acc, x)
                        });
    string.pop();
    string
}

extern crate pcap;
#[macro_use] extern crate nom;
extern crate pktparse;
extern crate dns_parser;
extern crate tls_parser;
extern crate dhcp4r;
extern crate ansi_term;
extern crate threadpool;
extern crate num_cpus;
extern crate clap;

use pcap::Device;
use pcap::Capture;

use ansi_term::Colour::{Yellow, Blue, Green};
use threadpool::ThreadPool;

use std::thread;
use std::sync::mpsc;

mod centrifuge;
mod structs;
mod nom_http;

use clap::{App, Arg};


type Message = structs::raw::Raw;
type Sender = mpsc::Sender<Message>;
type Receiver = mpsc::Receiver<Message>;


fn main() {
    let matches = App::new("sniffglue")
        .version("0.1.0")
        .arg(Arg::with_name("promisc")
            .short("p")
            .long("promisc")
            .help("Set device to promisc")
        )
        .arg(Arg::with_name("noisy")
            .short("x")
            .long("noisy")
            .help("Log noisy packets")
        )
        .arg(Arg::with_name("dev")
            .help("Device for sniffing")
        )
        .get_matches();

    let dev = match matches.value_of("dev") {
        Some(dev) => dev.to_owned(),
        None => Device::lookup().unwrap().name,
    };
    let log_noise = matches.occurrences_of("noisy") > 0;
    let promisc = matches.occurrences_of("promisc") > 0;

    println!("dev: {:?}", dev);
    let mut cap = Capture::from_device(dev.as_str()).unwrap()
                    .promisc(promisc)
                    .open().unwrap();

    let (tx, rx): (Sender, Receiver) = mpsc::channel();

    let join = thread::spawn(move || {
        let cpus = num_cpus::get();
        let pool = ThreadPool::new(cpus);

        while let Ok(packet) = cap.next() {
            // let ts = packet.header.ts;
            // let len = packet.header.len;

            let tx = tx.clone();
            let packet = packet.data.to_vec();

            pool.execute(move || {
                match centrifuge::parse(&packet) {
                    Ok(packet) => {
                        if !log_noise && packet.is_noise() {
                            return;
                        }

                        tx.send(packet).unwrap()
                    }
                    Err(_) => (),
                };
            });
        }
    });

    for packet in rx.iter() {
        use structs::prelude::*;
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

    join.join().unwrap();
}

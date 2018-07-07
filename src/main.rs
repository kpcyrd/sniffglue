#![warn(unused_extern_crates)]
extern crate sniffglue;
extern crate pcap;
extern crate pktparse;
extern crate ansi_term;
extern crate threadpool;
extern crate num_cpus;
extern crate reduce;
extern crate clap;
extern crate atty;
extern crate env_logger;
extern crate serde_json;
extern crate sha2;

use pcap::Device;
use pcap::Capture;

use threadpool::ThreadPool;

use std::thread;
use std::sync::mpsc;

mod fmt;
use sniffglue::centrifuge;
use sniffglue::link::DataLink;
use sniffglue::sandbox;
use sniffglue::structs;

use clap::{App, Arg, AppSettings};


type Message = structs::raw::Raw;
type Sender = mpsc::Sender<Message>;
type Receiver = mpsc::Receiver<Message>;


// XXX: workaround, remove if possible
enum CapWrap {
    Active(Capture<pcap::Active>),
    Offline(Capture<pcap::Offline>),
}

impl CapWrap {
    fn activate(self) -> Capture<pcap::Activated> {
        match self {
            CapWrap::Active(cap) => cap.into(),
            CapWrap::Offline(cap) => cap.into(),
        }
    }
}

impl From<Capture<pcap::Active>> for CapWrap {
    fn from(cap: Capture<pcap::Active>) -> CapWrap {
        CapWrap::Active(cap)
    }
}

impl From<Capture<pcap::Offline>> for CapWrap {
    fn from(cap: Capture<pcap::Offline>) -> CapWrap {
        CapWrap::Offline(cap)
    }
}


fn main() {
    // this goes before the sandbox so logging is available
    env_logger::init();

    sandbox::activate_stage1().expect("init sandbox stage1");

    let matches = App::new("sniffglue")
        .version(env!("CARGO_PKG_VERSION"))
        .setting(AppSettings::ColoredHelp)
        .arg(Arg::with_name("promisc")
            .short("p")
            .long("promisc")
            .help("Set device to promisc")
        )
        .arg(Arg::with_name("detailed")
            .short("d")
            .long("detailed")
            .help("Detailed output")
        )
        .arg(Arg::with_name("json")
            .short("j")
            .long("json")
            .help("Json output (unstable!)")
        )
        .arg(Arg::with_name("verbose")
            .short("v")
            .long("verbose")
            .multiple(true)
            .help("Show more packets (maximum: 4)")
        )
        .arg(Arg::with_name("read")
            .short("r")
            .long("read")
            .help("Open device as pcap file")
        )
        .arg(Arg::with_name("device")
            .help("Device for sniffing")
        )
        .get_matches();

    let device = match matches.value_of("device") {
        Some(device) => device.to_string(),
        None => Device::lookup().unwrap().name,
    };
    let verbose = matches.occurrences_of("verbose");
    let promisc = matches.is_present("promisc");

    let layout = if matches.is_present("json") {
        fmt::Layout::Json
    } else if matches.is_present("detailed") {
        fmt::Layout::Detailed
    } else {
        fmt::Layout::Compact
    };

    let colors = atty::is(atty::Stream::Stdout);
    let config = fmt::Config::new(layout, verbose, colors);

    let cap: CapWrap = if !matches.is_present("read") {
        match Capture::from_device(device.as_str()).unwrap()
                .promisc(promisc)
                .open() {
            Ok(cap) => {
                eprintln!("Listening on device: {:?}", device);
                cap.into()
            },
            Err(e) => {
                eprintln!("Failed to open interface {:?}: {}", device, e);
                return;
            },
        }
    } else {
        match Capture::from_file(device.as_str()) {
            Ok(cap) => {
                eprintln!("Reading from file: {:?}", device);
                cap.into()
            },
            Err(e) => {
                eprintln!("Failed to open pcap file {:?}: {}", device, e);
                return;
            },
        }
    };


    let (tx, rx): (Sender, Receiver) = mpsc::channel();
    let filter = config.filter();

    sandbox::activate_stage2().expect("init sandbox stage2");

    let join = thread::spawn(move || {
        let cpus = num_cpus::get();
        let pool = ThreadPool::new(cpus);

        let mut cap = cap.activate();

        let datalink = match DataLink::from_linktype(cap.get_datalink()) {
            Ok(link) => link,
            Err(x) => {
                // TODO: properly exit the program
                eprintln!("Unknown link type: {:?}, {:?}, {}",
                    x.get_name().unwrap_or("???".into()),
                    x.get_description().unwrap_or("???".into()),
                    x.0);
                return;
            },
        };

        while let Ok(packet) = cap.next() {
            // let ts = packet.header.ts;
            // let len = packet.header.len;

            let tx = tx.clone();
            let packet = packet.data.to_vec();

            let filter = filter.clone();
            let datalink = datalink.clone();
            pool.execute(move || {
                let packet = centrifuge::parse(&datalink, &packet);
                if filter.matches(&packet) {
                    tx.send(packet).unwrap()
                }
            });
        }
    });

    let format = config.format();
    for packet in rx.iter() {
        format.print(packet);
    }

    join.join().unwrap();
}

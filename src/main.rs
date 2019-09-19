#![warn(unused_extern_crates)]
extern crate sniffglue;
extern crate pcap;
extern crate pktparse;
extern crate ansi_term;
extern crate threadpool;
extern crate num_cpus;
extern crate reduce;
#[macro_use] extern crate structopt;
extern crate atty;
extern crate env_logger;
extern crate serde_json;
extern crate sha2;
extern crate pcap_file;

use pcap::Device;
use pcap::Capture;

use pcap_file::PcapWriter;

use threadpool::ThreadPool;

use std::thread;
use std::sync::mpsc;
use std::path::Path;
use std::fs::File;
use std::convert::TryInto;

mod cli;
mod fmt;
use cli::Args;
use sniffglue::centrifuge;
use sniffglue::link::DataLink;
use sniffglue::sandbox;
use sniffglue::structs;

use structopt::StructOpt;


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
    let pcap_out = File::create("test.pcap").expect("Error creating pcap file");
    let mut pcap_writer = PcapWriter::new(pcap_out).unwrap();

    let args = Args::from_args();

    let device = match args.device {
        Some(device) => device,
        None => Device::lookup().unwrap().name,
    };
    
    let layout = if args.json {
        fmt::Layout::Json
    } else if args.detailed {
        fmt::Layout::Detailed
    } else {
        fmt::Layout::Compact
    };

    let cpus = args.cpus.unwrap_or_else(num_cpus::get);

    let colors = atty::is(atty::Stream::Stdout);
    let config = fmt::Config::new(layout, args.verbose, colors);

    let cap: CapWrap = if !args.read {
        match Capture::from_device(device.as_str()).unwrap()
                .promisc(args.promisc)
                .open() {
            Ok(cap) => {
                let verbosity = config.filter().verbosity;
                eprintln!("Listening on device: {:?}, verbosity {}/4", device, verbosity);
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
        let pool = ThreadPool::new(cpus);

        let mut cap = cap.activate();

        let datalink = match DataLink::from_linktype(cap.get_datalink()) {
            Ok(link) => link,
            Err(x) => {
                // TODO: properly exit the program
                eprintln!("Unknown link type: {:?}, {:?}, {}",
                    x.get_name().unwrap_or_else(|_| "???".into()),
                    x.get_description().unwrap_or_else(|_| "???".into()),
                    x.0);
                return;
            },
        };


        while let Ok(packet) = cap.next() {
            let sec : u32 = packet.header.ts.tv_sec.try_into().unwrap();
            let usec : u32 = packet.header.ts.tv_usec.try_into().unwrap();
            // let len = packet.header.len;

            let tx = tx.clone();
            // let packet = packet.clone();
            let packet_data = packet.data.to_vec();

            let filter = filter.clone();
            let datalink = datalink.clone();
            pool.execute(move || {
                let packet_data = centrifuge::parse(&datalink, &packet_data);
                if filter.matches(&packet_data) {
                    //temporarily write it out to file
                    tx.send(packet_data).unwrap()
                }
            });
        }
    });

    // pcap outfile
    // pcap_writer.write(sec, usec, packet.data);

    let format = config.format();
    for packet in rx.iter() {
        format.print(packet);
    }

    join.join().unwrap();
}

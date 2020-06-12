use std::sync::{mpsc, Arc, Mutex};
use std::thread;

mod cli;
mod fmt;
use crate::cli::Args;
use sniffglue::centrifuge;
use sniffglue::errors::*;
use sniffglue::link::DataLink;
use sniffglue::sandbox;
use sniffglue::sniff;
use sniffglue::structs;

use structopt::StructOpt;

fn run() -> Result<()> {
    // this goes before the sandbox so logging is available
    env_logger::init();

    sandbox::activate_stage1().context("Failed to init sandbox stage1")?;

    let args = Args::from_args();

    let device = if let Some(dev) = args.device {
        dev
    } else {
        sniff::default_interface().context("Failed to find default interface")?
    };

    let layout = if args.json {
        fmt::Layout::Json
    } else if args.debugging {
        fmt::Layout::Debugging
    } else {
        fmt::Layout::Compact
    };

    let threads = args.threads.unwrap_or_else(num_cpus::get);

    let colors = atty::is(atty::Stream::Stdout);
    let config = fmt::Config::new(layout, args.verbose, colors);

    let cap = if !args.read {
        let cap = sniff::open(
            &device,
            &sniff::Config {
                promisc: args.promisc,
                immediate_mode: true,
            },
        )?;

        let verbosity = config.filter().verbosity;
        eprintln!(
            "Listening on device: {:?}, verbosity {}/4",
            device, verbosity
        );
        cap
    } else {
        let cap = sniff::open_file(&device)?;
        eprintln!("Reading from file: {:?}", device);
        cap
    };

    let datalink = DataLink::from_linktype(cap.datalink())?;

    let filter = config.filter();
    let (tx, rx) = mpsc::sync_channel(256);
    let cap = Arc::new(Mutex::new(cap));

    sandbox::activate_stage2().context("Failed to init sandbox stage2")?;

    for _ in 0..threads {
        let cap = cap.clone();
        let datalink = datalink.clone();
        let filter = filter.clone();
        let tx = tx.clone();
        thread::spawn(move || loop {
            let packet = {
                let mut cap = cap.lock().unwrap();
                cap.next()
            };

            if let Ok(Some(packet)) = packet {
                let packet = centrifuge::parse(&datalink, &packet.data);
                if filter.matches(&packet) {
                    tx.send(packet).unwrap()
                }
            } else {
                break;
            }
        });
    }
    drop(tx);

    let format = config.format();
    for packet in rx.iter() {
        format.print(packet);
    }

    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("Error: {}", err);
        for cause in err.iter_chain().skip(1) {
            eprintln!("Because: {}", cause);
        }
        std::process::exit(1);
    }
}

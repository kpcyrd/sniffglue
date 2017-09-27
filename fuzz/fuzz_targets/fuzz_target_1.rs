#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate sniffglue;

fuzz_target!(|data: &[u8]| {
    let packet = sniffglue::centrifuge::parse(&data);
    println!("Packet: {:?}", packet);
});

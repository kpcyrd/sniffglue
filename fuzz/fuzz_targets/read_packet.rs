#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate sniffglue;

fuzz_target!(|data: &[u8]| {
    let _ = sniffglue::centrifuge::parse_eth(&data);
});

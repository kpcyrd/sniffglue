extern crate base64;
extern crate sniffglue;
extern crate env_logger;

use std::env;

fn main() {
    env_logger::init();

    for arg in env::args().skip(1) {
        let bytes = base64::decode(&arg).unwrap();
        println!("{:?}", bytes);

        let packet = sniffglue::centrifuge::parse_eth(&bytes);
        println!("{:?}", packet);
    }
}

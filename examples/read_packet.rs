extern crate base64;
extern crate sniffglue;

use std::env;

fn main() {
    for arg in env::args().skip(1) {
        let bytes = base64::decode(&arg).unwrap();
        println!("{:?}", bytes);

        let packet = sniffglue::centrifuge::parse(&bytes);
        println!("{:?}", packet);
    }
}

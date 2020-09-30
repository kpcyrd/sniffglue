use serde::Serialize;

#[derive(Debug, PartialEq, Serialize)]
pub struct CjdnsEthPkt {
    pub version: u16,
    pub password: Vec<u8>,
    pub pubkey: Vec<u8>,
}

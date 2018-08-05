use std::str::from_utf8;

use pktparse::tcp::{self, TcpHeader};

use centrifuge::http;
use centrifuge::tls;

use structs::CentrifugeError;
use structs::tcp::TCP;


pub fn parse(remaining: &[u8]) -> Result<(tcp::TcpHeader, TCP), CentrifugeError> {
    if let Ok((remaining, tcp_hdr)) = tcp::parse_tcp_header(remaining) {
        let inner = match extract(&tcp_hdr, remaining) {
            Ok(x) => x,
            Err(_) => unknown(remaining),
        };
        Ok((tcp_hdr, inner))
    } else {
        Err(CentrifugeError::InvalidPacket)
    }
}

#[inline]
pub fn extract(tcp_hdr: &TcpHeader, remaining: &[u8]) -> Result<TCP, CentrifugeError> {
    if remaining.is_empty() {
        Ok(TCP::Binary(Vec::new()))
    } else if tcp_hdr.dest_port == 443 {
        let client_hello = tls::extract(remaining)?;
        Ok(TCP::TLS(client_hello))
    } else if tcp_hdr.source_port == 443 {
        // ignore
        /*
        if tcp_hdr.source_port == 443 {
            let x = tls_parser::parse_tls_plaintext(remaining);
            println!("tls(in): {:?}", &x);
        }
        */
        Err(CentrifugeError::UnknownProtocol)
    } else if tcp_hdr.dest_port == 80 {
        let http = http::extract(remaining)?;
        Ok(TCP::HTTP(http))
    } else {
        Err(CentrifugeError::UnknownProtocol)
    }
}

#[inline]
pub fn unknown(remaining: &[u8]) -> TCP {
    // if slice contains null bytes, don't try to decode
    if remaining.contains(&0) {
        TCP::Binary(remaining.to_vec())
    } else {
        match from_utf8(remaining) {
            Ok(remaining) => TCP::Text(remaining.to_owned()),
            Err(_) => TCP::Binary(remaining.to_vec()),
        }
    }
}

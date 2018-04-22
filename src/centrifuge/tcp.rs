use std::str::from_utf8;

use nom::IResult::Done;
use pktparse::tcp;

use centrifuge::http;
use centrifuge::tls;

use structs::CentrifugeError;
use structs::tcp::TCP;


pub fn extract(remaining: &[u8]) -> Result<(tcp::TcpHeader, TCP), CentrifugeError> {
    if let Done(remaining, tcp_hdr) = tcp::parse_tcp_header(remaining) {
        if remaining.is_empty() {
            return Err(CentrifugeError::InvalidPacket);
        }

        if tcp_hdr.dest_port == 443 {
            let client_hello = tls::extract(remaining)?;
            Ok((tcp_hdr, TCP::TLS(client_hello)))
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
            Ok((tcp_hdr, TCP::HTTP(http)))
        } else {
            match from_utf8(remaining) {
                Ok(remaining) => Ok((tcp_hdr, TCP::Text(remaining.to_owned()))),
                Err(_) => Ok((tcp_hdr, TCP::Binary(remaining.to_vec()))),
            }
        }
    } else {
        Err(CentrifugeError::InvalidPacket)
    }
}

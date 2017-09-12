use std::str::from_utf8;

use nom::IResult::Done;
use tls_parser;
use tls_parser::tls::{TlsMessage, TlsMessageHandshake};
use tls_parser::tls_extensions::{TlsExtension, parse_tls_extension};

use structs::{self, CentrifugeError};


pub fn extract(remaining: &[u8]) -> Result<structs::tls::ClientHello, CentrifugeError> {
    if let Done(_remaining, tls) = tls_parser::parse_tls_plaintext(remaining) {
        for msg in tls.msg {
            match msg {
                TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) => {
                    let mut hostname = None;

                    let mut remaining = ch.ext.unwrap();
                    while let Done(remaining2, ext) = parse_tls_extension(remaining) {
                        remaining = remaining2;
                        match ext {
                            TlsExtension::SNI(sni) => {
                                for s in sni {
                                    let name = from_utf8(s.1).unwrap();
                                    hostname = Some(name.to_owned());
                                }
                            },
                            _ => (),
                        }
                    }

                    return Ok(structs::tls::ClientHello::new(hostname));
                },
                _ => (),
            };
        }

        Err(CentrifugeError::ParsingError)
    } else {
        Err(CentrifugeError::WrongProtocol)
    }
}

use std::str;

use crate::structs::tls::{ClientHello, ServerHello, TLS};
use crate::structs::{tls, CentrifugeError};
use tls_parser;
use tls_parser::tls::{TlsMessage, TlsMessageHandshake};
use tls_parser::tls_extensions::{parse_tls_extension, TlsExtension};

pub fn extract(remaining: &[u8]) -> Result<tls::TLS, CentrifugeError> {
    if let Ok((_remaining, tls)) = tls_parser::parse_tls_plaintext(remaining) {
        for msg in tls.msg {
            match msg {
                TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) => {
                    let mut hostname = None;

                    if let Some(mut remaining) = ch.ext {
                        while let Ok((remaining2, ext)) = parse_tls_extension(remaining) {
                            remaining = remaining2;
                            if let TlsExtension::SNI(sni) = ext {
                                for s in sni {
                                    let name = str::from_utf8(s.1)
                                        .map_err(|_| CentrifugeError::ParsingError)?;
                                    hostname = Some(name.to_owned());
                                }
                            }
                        }

                        return Ok(TLS::ClientHello(ClientHello::new(ch, hostname)));
                    }
                }
                TlsMessage::Handshake(TlsMessageHandshake::ServerHello(sh)) => {
                    return Ok(TLS::ServerHello(ServerHello::new(sh)));
                }
                _ => (),
            }
        }

        Err(CentrifugeError::ParsingError)
    } else {
        Err(CentrifugeError::WrongProtocol)
    }
}

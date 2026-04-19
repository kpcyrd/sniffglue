use crate::structs::tls::{ClientHello, ServerHello, TLS};
use crate::structs::{CentrifugeError, tls};
use std::str;
use tls_parser::{TlsExtension, TlsMessage, TlsMessageHandshake, parse_tls_extension};

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

                        return Ok(TLS::ClientHello(ClientHello::new(&ch, hostname)));
                    }
                }
                TlsMessage::Handshake(TlsMessageHandshake::ServerHello(sh)) => {
                    return Ok(TLS::ServerHello(ServerHello::new(&sh)));
                }
                _ => (),
            }
        }

        Err(CentrifugeError::ParsingError)
    } else {
        Err(CentrifugeError::WrongProtocol)
    }
}

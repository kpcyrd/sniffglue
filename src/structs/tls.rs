use data_encoding::BASE64;
use serde::Serialize;
use tls_parser::{TlsVersion, TlsClientHelloContents, TlsServerHelloContents};

#[derive(Debug, PartialEq, Serialize)]
pub enum TLS {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
}

fn tls_version(ver: TlsVersion) -> Option<&'static str> {
    match ver {
        TlsVersion::Ssl30 => Some("ssl3.0"),
        TlsVersion::Tls10 => Some("tls1.0"),
        TlsVersion::Tls11 => Some("tls1.1"),
        TlsVersion::Tls12 => Some("tls1.2"),
        TlsVersion::Tls13 => Some("tls1.3"),
        _                 => None,
    }
}

#[derive(Debug, PartialEq, Serialize)]
pub struct ClientHello {
    pub version: Option<&'static str>,
    pub session_id: Option<String>,
    pub hostname: Option<String>,
}

impl ClientHello {
    pub fn new(ch: &TlsClientHelloContents, hostname: Option<String>) -> ClientHello {
        let session_id = ch.session_id.map(|id| BASE64.encode(id));

        ClientHello {
            version: tls_version(ch.version),
            session_id,
            hostname,
        }
    }
}

#[derive(Debug, PartialEq, Serialize)]
pub struct ServerHello {
    pub version: Option<&'static str>,
    pub session_id: Option<String>,
    pub cipher: Option<&'static str>,
}

impl ServerHello {
    pub fn new(sh: &TlsServerHelloContents) -> ServerHello {
        let cipher = sh.cipher.get_ciphersuite()
            .map(|cs| cs.name);
        let session_id = sh.session_id.map(|id| BASE64.encode(id));

        ServerHello {
            version: tls_version(sh.version),
            session_id,
            cipher,
        }
    }
}

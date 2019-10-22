#[derive(Debug, PartialEq)]
pub enum CentrifugeError {
    WrongProtocol,
    ParsingError,

    UnknownProtocol,
    InvalidPacket,
}

pub mod prelude {
    pub use structs::raw::Raw::*;
    pub use structs::ether::Ether::*;
}

/// Zero            - This packet is very interesting
/// One             - This packet is somewhat interesting
/// Two             - Stuff you want to see if you're looking really hard
/// AlmostMaximum   - Some binary data
/// Maximum         - We couldn't parse this
#[derive(Debug)]
pub enum NoiseLevel {
    Zero          = 0,
    One           = 1,
    Two           = 2,
    AlmostMaximum = 3,
    Maximum       = 4,
}

impl NoiseLevel {
    pub fn into_u8(self) -> u8 {
        self as u8
    }
}

pub mod raw {
    use structs::ether;
    use structs::NoiseLevel;
    use pktparse;

    #[derive(Debug, PartialEq, Serialize)]
    pub enum Raw {
        Ether(pktparse::ethernet::EthernetFrame, ether::Ether),
        Tun(ether::Ether),
        Unknown(Vec<u8>),
    }

    impl Raw {
        pub fn noise_level(&self) -> NoiseLevel {
            use self::Raw::*;
            match *self {
                Ether(_, ref ether) => ether.noise_level(),
                Tun(ref ether) => ether.noise_level(),
                Unknown(_) => NoiseLevel::Maximum,
            }
        }
    }
}

pub mod ether {
    use structs::arp;
    use structs::ipv4;
    use structs::ipv6;
    use structs::cjdns;
    use structs::NoiseLevel;
    use pktparse;

    #[derive(Debug, PartialEq, Serialize)]
    pub enum Ether {
        Arp(arp::ARP),
        IPv4(pktparse::ipv4::IPv4Header, ipv4::IPv4),
        IPv6(pktparse::ipv6::IPv6Header, ipv6::IPv6),
        Cjdns(cjdns::CjdnsEthPkt),
        Unknown(Vec<u8>),
    }

    impl Ether {
        pub fn noise_level(&self) -> NoiseLevel {
            use self::Ether::*;
            match *self {
                Arp(_) => NoiseLevel::One,
                IPv4(_, ref ipv4) => ipv4.noise_level(),
                IPv6(_, ref ipv6) => ipv6.noise_level(),
                Cjdns(_) => NoiseLevel::Two,
                Unknown(_) => NoiseLevel::Maximum,
            }
        }
    }
}

pub mod arp {
    use pktparse;

    #[derive(Debug, PartialEq, Serialize)]
    pub enum ARP {
        Request(pktparse::arp::ArpPacket),
        Reply(pktparse::arp::ArpPacket),
    }
}

pub mod cjdns {
    #[derive(Debug, PartialEq, Serialize)]
    pub struct CjdnsEthPkt {
        pub version: u16,
        pub password: Vec<u8>,
        pub pubkey: Vec<u8>,
    }
}

pub mod ipv4 {
    use structs::tcp;
    use structs::udp;
    use structs::NoiseLevel;
    use pktparse;

    #[derive(Debug, PartialEq, Serialize)]
    pub enum IPv4 {
        TCP(pktparse::tcp::TcpHeader, tcp::TCP),
        UDP(pktparse::udp::UdpHeader, udp::UDP),
        Unknown(Vec<u8>),
    }

    impl IPv4 {
        pub fn noise_level(&self) -> NoiseLevel {
            use self::IPv4::*;
            match *self {
                TCP(ref header, ref tcp) => tcp.noise_level(header),
                UDP(_, ref udp) => udp.noise_level(),
                Unknown(_) => NoiseLevel::Maximum,
            }
        }
    }
}

pub mod ipv6 {
    use structs::tcp;
    use structs::udp;
    use structs::NoiseLevel;
    use pktparse;

    #[derive(Debug, PartialEq, Serialize)]
    pub enum IPv6 {
        TCP(pktparse::tcp::TcpHeader, tcp::TCP),
        UDP(pktparse::udp::UdpHeader, udp::UDP),
        Unknown(Vec<u8>),
    }

    impl IPv6 {
        pub fn noise_level(&self) -> NoiseLevel {
            use self::IPv6::*;
            match *self {
                TCP(ref header, ref tcp) => tcp.noise_level(header),
                UDP(_, ref udp) => udp.noise_level(),
                Unknown(_) => NoiseLevel::Maximum,
            }
        }
    }
}

pub mod ip {
    use pktparse::{ipv4, ipv6};
    use std::fmt::Display;
    use std::net::Ipv4Addr;

    pub trait IPHeader {
        type Addr: Display;

        fn source_addr(&self) -> Self::Addr;
        fn dest_addr(&self) -> Self::Addr;
    }

    impl IPHeader for ipv4::IPv4Header {
        type Addr = Ipv4Addr;

        #[inline]
        fn source_addr(&self) -> Self::Addr {
            self.source_addr
        }

        #[inline]
        fn dest_addr(&self) -> Self::Addr {
            self.dest_addr
        }
    }

    impl IPHeader for ipv6::IPv6Header {
        type Addr = String;

        #[inline]
        fn source_addr(&self) -> Self::Addr {
            format!("[{}]", self.source_addr)
        }

        #[inline]
        fn dest_addr(&self) -> Self::Addr {
            format!("[{}]", self.dest_addr)
        }
    }
}

pub mod tcp {
    use structs::tls;
    use structs::http;
    use structs::NoiseLevel;

    #[derive(Debug, PartialEq, Serialize)]
    pub enum TCP {
        TLS(tls::TLS),
        HTTP(http::Request),

        Text(String),
        Binary(Vec<u8>),
        Empty,
    }

    impl TCP {
        pub fn noise_level(&self, header: &pktparse::tcp::TcpHeader) -> NoiseLevel {
            use self::TCP::*;
            match *self {
                Text(ref text) if text.len() <= 8 => NoiseLevel::AlmostMaximum,
                Binary(_) => NoiseLevel::AlmostMaximum,
                Empty => if !header.flag_rst &&
                            !header.flag_syn &&
                            !header.flag_fin {
                    NoiseLevel::AlmostMaximum
                } else {
                    NoiseLevel::Two
                },
                _ => NoiseLevel::Zero,
            }
        }
    }
}

pub mod udp {
    use structs::dns;
    use structs::dhcp;
    use structs::ssdp;
    use structs::dropbox;
    use structs::NoiseLevel;

    #[derive(Debug, PartialEq, Serialize)]
    pub enum UDP {
        DHCP(dhcp::DHCP),
        DNS(dns::DNS),
        SSDP(ssdp::SSDP),
        Dropbox(dropbox::DropboxBeacon),

        Text(String),
        Binary(Vec<u8>),
    }

    impl UDP {
        pub fn noise_level(&self) -> NoiseLevel {
            use self::UDP::*;
            match *self {
                DHCP(_) => NoiseLevel::Zero,
                DNS(_) => NoiseLevel::Zero,
                SSDP(_) => NoiseLevel::Two,
                Dropbox(_) => NoiseLevel::Two,
                Text(_) => NoiseLevel::Two,
                Binary(_) => NoiseLevel::AlmostMaximum,
            }
        }
    }
}

pub mod tls {
    use base64;
    use tls_parser::TlsClientHelloContents;
    use tls_parser::TlsServerHelloContents;
    use tls_parser::tls::TlsVersion;

    #[derive(Debug, PartialEq, Serialize)]
    pub enum TLS {
        ClientHello(ClientHello),
        ServerHello(ServerHello),
    }

    fn tls_version(ver: &TlsVersion) -> Option<&'static str> {
        match *ver {
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
        pub fn new(ch: TlsClientHelloContents, hostname: Option<String>) -> ClientHello {
            let session_id = ch.session_id.map(base64::encode);

            ClientHello {
                version: tls_version(&ch.version),
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
        pub fn new(sh: TlsServerHelloContents) -> ServerHello {
            let cipher = sh.cipher.get_ciphersuite()
                .map(|cs| cs.name);
            let session_id = sh.session_id.map(base64::encode);

            ServerHello {
                version: tls_version(&sh.version),
                session_id,
                cipher,
            }
        }
    }
}

pub mod http {
    use std::str::from_utf8;
    use std::string::FromUtf8Error;
    use nom_http;

    #[derive(Debug, PartialEq, Serialize)]
    pub struct Request {
        pub method: String,
        pub uri: String,
        pub version: String,
        pub host: Option<String>,
        pub agent: Option<String>,
        pub referer: Option<String>,
        pub auth: Option<String>,
        pub cookies: Option<String>,
    }

    fn mkheader(x: Vec<&[u8]>) -> Option<String> {
        String::from_utf8(x.into_iter()
            .flat_map(|x| x.to_owned())
            .collect(),
        ).ok()
    }

    impl Request {
        pub fn from_nom(req: &nom_http::Request, headers: Vec<nom_http::Header>) -> Result<Request, FromUtf8Error> {
            let mut host = None;
            let mut agent = None;
            let mut referer = None;
            let mut auth = None;
            let mut cookies = None;

            for header in headers {
                if let Ok(name) = from_utf8(header.name) {
                    match name.to_lowercase().as_str() {
                        "host" => host = mkheader(header.value),
                        "user-agent" => agent = mkheader(header.value),
                        "referer" => referer = mkheader(header.value),
                        "authorization" => auth = mkheader(header.value),
                        "cookie" => cookies = mkheader(header.value),
                        _ => (),
                    }
                }
            }

            Ok(Request {
                method: String::from_utf8(req.method.to_vec())?,
                uri: String::from_utf8(req.uri.to_vec())?,
                version: String::from_utf8(req.version.to_vec())?,

                host,
                agent,
                referer,
                auth,
                cookies,
            })
        }
    }
}

pub mod dhcp {
    use std::net::Ipv4Addr;

    #[derive(Debug, PartialEq, Serialize)]
    pub enum DHCP {
        ACK(Packet),
        DECLINE(Packet),
        DISCOVER(Packet),
        INFORM(Packet),
        NAK(Packet),
        OFFER(Packet),
        RELEASE(Packet),
        REQUEST(Packet),
        UNKNOWN(Packet),
    }

    #[derive(Debug, PartialEq, Serialize)]
    pub enum DhcpOption {
        String(String),
        IPv4(Ipv4Addr),
        Bytes(Vec<u8>),
    }

    #[derive(Debug, PartialEq, Serialize)]
    pub struct Packet {
        pub ciaddr: Ipv4Addr,
        pub yiaddr: Ipv4Addr,
        pub siaddr: Ipv4Addr,
        pub chaddr: [u8; 6],

        pub hostname: Option<DhcpOption>,
        pub requested_ip_address: Option<DhcpOption>,
        pub router: Option<DhcpOption>,
        pub domain_name_server: Option<DhcpOption>,
    }

    impl Packet {
        pub fn new(ciaddr: Ipv4Addr, yiaddr: Ipv4Addr, siaddr: Ipv4Addr, chaddr: [u8; 6]) -> Packet {
            Packet {
                ciaddr,
                yiaddr,
                siaddr,
                chaddr,

                hostname: None,
                requested_ip_address: None,
                router: None,
                domain_name_server: None,
            }
        }
    }
}

pub mod dns {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use dns_parser;

    // https://github.com/tailhook/dns-parser/pull/34
    #[derive(Debug, PartialEq, Serialize)]
    pub enum QueryType {
        A,
        NS,
        MF,
        CNAME,
        SOA,
        MB,
        MG,
        MR,
        NULL,
        WKS,
        PTR,
        HINFO,
        MINFO,
        MX,
        TXT,
        AAAA,
        SRV,
        AXFR,
        MAILB,
        MAILA,
        All,
    }

    impl From<dns_parser::QueryType> for QueryType {
        #[inline]
        fn from(qt: dns_parser::QueryType) -> QueryType {
            use dns_parser::QueryType::*;
            match qt {
                A => QueryType::A,
                NS => QueryType::NS,
                MF => QueryType::MF,
                CNAME => QueryType::CNAME,
                SOA => QueryType::SOA,
                MB => QueryType::MB,
                MG => QueryType::MG,
                MR => QueryType::MR,
                NULL => QueryType::NULL,
                WKS => QueryType::WKS,
                PTR => QueryType::PTR,
                HINFO => QueryType::HINFO,
                MINFO => QueryType::MINFO,
                MX => QueryType::MX,
                TXT => QueryType::TXT,
                AAAA => QueryType::AAAA,
                SRV => QueryType::SRV,
                AXFR => QueryType::AXFR,
                MAILB => QueryType::MAILB,
                MAILA => QueryType::MAILA,
                All => QueryType::All,
            }
        }
    }

    #[derive(Debug, PartialEq, Serialize)]
    pub enum DNS {
        Request(Request),
        Response(Response),
    }

    #[derive(Debug, PartialEq, Serialize)]
    pub struct Request {
        pub questions: Vec<(QueryType, String)>,
    }

    impl Request {
        pub fn new(questions: Vec<(QueryType, String)>) -> Request {
            Request {
                questions,
            }
        }

        pub fn wrap(self) -> DNS {
            DNS::Request(self)
        }
    }

    #[derive(Debug, PartialEq, Serialize)]
    pub struct Response {
        pub answers: Vec<(String, Record)>,
    }

    impl Response {
        pub fn new(answers: Vec<(String, Record)>) -> Response {
            Response {
                answers,
            }
        }

        pub fn wrap(self) -> DNS {
            DNS::Response(self)
        }
    }

    #[derive(Debug, PartialEq, Serialize)]
    pub enum Record {
        A(Ipv4Addr),
        AAAA(Ipv6Addr),
        CNAME(String),
        NS(String),
        PTR(String),
        TXT(String),
        Unknown,
    }

    impl<'a> From<dns_parser::RData<'a>> for Record {
        fn from(rdata: dns_parser::RData) -> Record {
            use dns_parser::RData::*;

            match rdata {
                A(addr) => Record::A(addr.0),
                AAAA(addr) => Record::AAAA(addr.0),
                CNAME(name) => Record::CNAME(name.to_string()),
                NS(name) => Record::NS(name.to_string()),
                PTR(name) => Record::PTR(name.to_string()),
                TXT(data) => {
                    let mut x = Vec::new();

                    for r in data.iter() {
                        x.extend(r);
                    }

                    Record::TXT(String::from_utf8_lossy(&x).to_string())
                },
                _ => Record::Unknown,
            }
        }
    }
}

pub mod ssdp {
    #[derive(Debug, PartialEq, Serialize)]
    pub enum SSDP {
        Discover(Option<String>),
        Notify(String),
        BTSearch(String),
    }
}

pub mod dropbox {
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct DropboxBeacon {
        pub version: Vec<u8>,
        pub host_int: u128,
        pub namespaces: Vec<u64>,
        pub displayname: String,
        pub port: u16,
    }
}

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
    pub use structs::ipv4::IPv4::*;
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
    pub fn to_u64(self) -> u64 {
        self as u64
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
    use structs::NoiseLevel;
    use pktparse;

    #[derive(Debug, PartialEq, Serialize)]
    pub enum Ether {
        Arp(arp::ARP),
        IPv4(pktparse::ipv4::IPv4Header, ipv4::IPv4),
        Unknown(Vec<u8>),
    }

    impl Ether {
        pub fn noise_level(&self) -> NoiseLevel {
            use self::Ether::*;
            match *self {
                Arp(_) => NoiseLevel::One,
                IPv4(_, ref ipv4) => ipv4.noise_level(),
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
                TCP(_, ref tcp) => tcp.noise_level(),
                UDP(_, ref udp) => udp.noise_level(),
                Unknown(_) => NoiseLevel::Maximum,
            }
        }
    }
}

pub mod tcp {
    use structs::tls;
    use structs::http;
    use structs::NoiseLevel;

    #[derive(Debug, PartialEq, Serialize)]
    pub enum TCP {
        TLS(tls::ClientHello),
        HTTP(http::Request),

        Text(String),
        Binary(Vec<u8>),
    }

    impl TCP {
        pub fn noise_level(&self) -> NoiseLevel {
            use self::TCP::*;
            match *self {
                Text(ref text) if text.len() < 5 => NoiseLevel::AlmostMaximum,
                Binary(_) => NoiseLevel::AlmostMaximum,
                _ => NoiseLevel::Zero,
            }
        }
    }
}

pub mod udp {
    use structs::dns;
    use structs::dhcp;
    use structs::ssdp;
    use structs::NoiseLevel;

    #[derive(Debug, PartialEq, Serialize)]
    pub enum UDP {
        DHCP(dhcp::DHCP),
        DNS(dns::DNS),
        SSDP(ssdp::SSDP),

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
                Text(_) => NoiseLevel::Two,
                Binary(_) => NoiseLevel::AlmostMaximum,
            }
        }
    }
}

pub mod tls {
    #[derive(Debug, PartialEq, Serialize)]
    pub struct ClientHello {
        pub hostname: Option<String>,
    }

    impl ClientHello {
        pub fn new(hostname: Option<String>) -> ClientHello {
            ClientHello {
                hostname,
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

    impl<'a> From<dns_parser::RRData<'a>> for Record {
        fn from(rrdata: dns_parser::RRData) -> Record {
            use dns_parser::RRData::*;

            match rrdata {
                A(addr) => Record::A(addr),
                AAAA(addr) => Record::AAAA(addr),
                CNAME(name) => Record::CNAME(name.to_string()),
                NS(name) => Record::NS(name.to_string()),
                PTR(name) => Record::PTR(name.to_string()),
                TXT(string) => Record::TXT(string),
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

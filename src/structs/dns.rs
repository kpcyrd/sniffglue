use serde::Serialize;
use std::net::{Ipv4Addr, Ipv6Addr};

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

impl From<dns_parser::RData<'_>> for Record {
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

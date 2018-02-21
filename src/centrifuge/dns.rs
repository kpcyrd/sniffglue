use dns_parser;
use structs::{self, CentrifugeError};

pub fn extract(remaining: &[u8]) -> Result<structs::dns::DNS, CentrifugeError> {
    if let Ok(dns) = dns_parser::Packet::parse(remaining) {
        if dns.header.query {
            // dns request
            let questions = dns.questions
                               .into_iter()
                               .map(|q| (q.qtype.into(), q.qname.to_string()))
                               .collect();

            Ok(structs::dns::Request::new(questions).wrap())
        } else {
            // dns response
            let answers = dns.answers
                             .into_iter()
                             .map(|a| (a.name.to_string(), structs::dns::Record::from(a.data)))
                             .collect();

            Ok(structs::dns::Response::new(answers).wrap())
        }
    } else {
        Err(structs::CentrifugeError::WrongProtocol)
    }
}

use bstr::BString;
use httparse::Header;
use crate::structs::CentrifugeError;
use serde::Serialize;
use std::convert::TryFrom;
use std::str;

#[derive(Debug, PartialEq, Serialize)]
pub struct Request {
    pub method: String,
    pub uri: String,
    pub version: String,
    pub headers: Vec<(String, BString)>,
    pub host: Option<String>,
    pub agent: Option<String>,
    pub referer: Option<String>,
    pub auth: Option<String>,
    pub cookies: Option<String>,
    pub body: Option<BString>,
}

fn append_if_header(mem: &mut Option<String>, expected: &str, header: &Header) {
    if header.name.eq_ignore_ascii_case(expected) {
        if let Ok(value) = str::from_utf8(header.value) {
            let mem = mem.get_or_insert_with(String::new);
            if !mem.is_empty() {
                mem.push_str("; ");
            }
            mem.push_str(value);
        }
    }
}

impl TryFrom<httparse::Request<'_, '_>> for Request {
    type Error = CentrifugeError;

    fn try_from(req: httparse::Request) -> Result<Request, CentrifugeError> {
        let Some(method) = req.method else { return Err(CentrifugeError::InvalidPacket) };
        let Some(uri) = req.path else { return Err(CentrifugeError::InvalidPacket) };
        let Some(version) = req.version else { return Err(CentrifugeError::InvalidPacket) };

        let mut out = Request {
            method: method.to_string(),
            uri: uri.to_string(),
            version: format!("HTTP/1.{version}"),
            headers: Vec::new(),
            host: None,
            agent: None,
            referer: None,
            auth: None,
            cookies: None,
            body: None,
        };

        for header in req.headers {
            out.headers.push((
                header.name.into(),
                header.value.into(),
            ));

            append_if_header(&mut out.host, "host", header);
            append_if_header(&mut out.agent, "user-agent", header);
            append_if_header(&mut out.referer, "referer", header);
            append_if_header(&mut out.auth, "authorization", header);
            append_if_header(&mut out.cookies, "cookie", header);
        }

        Ok(out)
    }
}

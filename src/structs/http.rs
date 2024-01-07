use bstr::BString;
use httparse::Header;
use crate::structs::CentrifugeError;
use serde::Serialize;
use std::convert::TryFrom;
use std::str;

#[derive(Debug, PartialEq, Serialize)]
pub enum Http {
    Request(Request),
    Response(Response),
}

#[derive(Debug, PartialEq, Serialize)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub version: u8,
    pub headers: Vec<(String, BString)>,
    pub host: Option<String>,
    pub agent: Option<String>,
    pub referer: Option<String>,
    pub auth: Option<String>,
    pub cookies: Option<String>,
    pub body: Option<BString>,
}

#[derive(Debug, PartialEq, Serialize)]
pub struct Response {
    pub code: u16,
    pub reason: String,
    pub version: u8,
    pub headers: Vec<(String, BString)>,
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
        let Some(path) = req.path else { return Err(CentrifugeError::InvalidPacket) };
        let Some(version) = req.version else { return Err(CentrifugeError::InvalidPacket) };

        let mut out = Request {
            method: method.to_string(),
            path: path.to_string(),
            version,
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

impl TryFrom<httparse::Response<'_, '_>> for Response {
    type Error = CentrifugeError;

    fn try_from(req: httparse::Response) -> Result<Response, CentrifugeError> {
        let Some(version) = req.version else { return Err(CentrifugeError::InvalidPacket) };
        let Some(code) = req.code else { return Err(CentrifugeError::InvalidPacket) };
        let Some(reason) = req.reason else { return Err(CentrifugeError::InvalidPacket) };

        let mut out = Response {
            version,
            code,
            reason: reason.to_string(),
            headers: Vec::new(),
            body: None,
        };

        for header in req.headers {
            out.headers.push((
                header.name.into(),
                header.value.into(),
            ));
        }

        Ok(out)
    }
}

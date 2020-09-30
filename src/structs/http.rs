use serde::Serialize;
use std::str::from_utf8;
use std::string::FromUtf8Error;
use crate::nom_http;

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

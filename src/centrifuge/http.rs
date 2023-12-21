use bstr::BString;
use crate::structs::CentrifugeError;
use crate::structs::http::{Http, Request, Response};
use httparse::Status;
use std::convert::TryFrom;

pub fn extract(remaining: &[u8]) -> Result<Http, CentrifugeError> {
    let mut req_headers = [httparse::EMPTY_HEADER; 256];
    let mut resp_headers = [httparse::EMPTY_HEADER; 256];

    let mut req = httparse::Request::new(&mut req_headers);
    let mut resp = httparse::Response::new(&mut resp_headers);

    if let Ok(status) = req.parse(remaining) {
        let remaining = match status {
            Status::Complete(n) => &remaining[n..],
            Status::Partial => &[],
        };

        let mut req = Request::try_from(req)?;
        if !remaining.is_empty() {
            req.body = Some(BString::from(remaining))
        }

        Ok(Http::Request(req))
    } else if let Ok(status) = resp.parse(remaining) {
        let remaining = match status {
            Status::Complete(n) => &remaining[n..],
            Status::Partial => &[],
        };

        let mut resp = Response::try_from(resp)?;
        if !remaining.is_empty() {
            resp.body = Some(BString::from(remaining))
        }

        Ok(Http::Response(resp))
    } else {
        Err(CentrifugeError::WrongProtocol)
    }
}

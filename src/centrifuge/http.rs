use bstr::BString;
use crate::structs::CentrifugeError;
use crate::structs::http::Request;
use httparse::Status;
use std::convert::TryFrom;

pub fn extract(remaining: &[u8]) -> Result<Request, CentrifugeError> {
    let mut headers = [httparse::EMPTY_HEADER; 256];
    let mut req = httparse::Request::new(&mut headers);
    let remaining = match req.parse(remaining) {
        Ok(Status::Complete(n)) => {
            &remaining[n..]
        },
        Ok(Status::Partial) => {
            &[]
        },
        Err(_) => return Err(CentrifugeError::WrongProtocol),
    };

    let mut req = Request::try_from(req)?;
    if !remaining.is_empty() {
        req.body = Some(BString::from(remaining))
    }
    Ok(req)
}

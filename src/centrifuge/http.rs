use crate::nom_http;

use crate::structs::CentrifugeError;
use crate::structs::http::Request;

pub fn extract(remaining: &[u8]) -> Result<Request, CentrifugeError> {
    if let Ok((_remaining, (request, headers))) = nom_http::request(remaining) {
        match Request::from_nom(&request, headers) {
            Ok(http) => Ok(http),
            Err(_) => Err(CentrifugeError::ParsingError),
        }
    } else {
        Err(CentrifugeError::WrongProtocol)
    }
}

use crate::structs::ssdp::SSDP;
use crate::structs::CentrifugeError;

pub fn parse_ssdp(data: &str) -> Result<SSDP, CentrifugeError> {
    if data.starts_with("M-SEARCH * HTTP/1.1\r\n") {
        let extra = &data[21..];
        let extra = if extra.is_empty() {
            None
        } else {
            Some(extra.to_string())
        };
        Ok(SSDP::Discover(extra))
    } else if data == "M-SEARCH * HTTP/1.0" {
        Ok(SSDP::Discover(None))
    } else if data.starts_with("NOTIFY * HTTP/1.1\r\n") {
        Ok(SSDP::Notify(data[19..].to_string()))
    } else if data.starts_with("BT-SEARCH * HTTP/1.1\r\n") {
        Ok(SSDP::BTSearch(data[22..].to_string()))
    } else {
        Err(CentrifugeError::UnknownProtocol)
    }
}

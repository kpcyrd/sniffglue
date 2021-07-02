use crate::structs::ssdp::SSDP;
use crate::structs::CentrifugeError;


pub fn parse_ssdp(data: &str) -> Result<SSDP, CentrifugeError> {
    if let Some(extra) = data.strip_prefix("M-SEARCH * HTTP/1.1\r\n") {
        let extra = if extra.is_empty() {
            None
        } else {
            Some(extra.to_string())
        };
        Ok(SSDP::Discover(extra))
    } else if data == "M-SEARCH * HTTP/1.0" {
        Ok(SSDP::Discover(None))
    } else if let Some(data) = data.strip_prefix("NOTIFY * HTTP/1.1\r\n") {
        Ok(SSDP::Notify(data.to_string()))
    } else if let Some(data) = data.strip_prefix("BT-SEARCH * HTTP/1.1\r\n") {
        Ok(SSDP::BTSearch(data.to_string()))
    } else {
        Err(CentrifugeError::UnknownProtocol)
    }
}

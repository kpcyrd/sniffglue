use std::str;

use crate::structs::{dropbox, CentrifugeError};
use serde_json;

pub fn extract(data: &[u8]) -> Result<dropbox::DropboxBeacon, CentrifugeError> {
    let data = str::from_utf8(data).map_err(|_| CentrifugeError::InvalidPacket)?;
    let beacon = serde_json::from_str(data).map_err(|_| CentrifugeError::InvalidPacket)?;
    Ok(beacon)
}

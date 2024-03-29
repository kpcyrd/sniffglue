use crate::errors::*;

#[derive(Debug, Clone)]
pub enum DataLink {
    Ethernet,
    Tun,
    Sll,
    RadioTap,
}

impl DataLink {
    pub fn from_linktype(linktype: i32) -> Result<DataLink> {
        match linktype {
            1 => {
                // LINKTYPE_ETHERNET
                Ok(DataLink::Ethernet)
            },
            12 => {
                // RAW IP (linux tun)
                Ok(DataLink::Tun)
            },
            113 => {
                // LINKTYPE_LINUX_SLL (eg. ppp)
                Ok(DataLink::Sll)
            }
            127 => {
                // LINKTYPE_IEEE802_11_RADIOTAP
                Ok(DataLink::RadioTap)
            },
            x => bail!("Unknown link type: {:?}", x),
        }
    }
}

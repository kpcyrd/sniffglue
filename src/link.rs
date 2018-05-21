use pcap;

#[derive(Debug, Clone)]
pub enum DataLink {
    Ethernet,
    Tun,
    RadioTap,
}

impl DataLink {
    pub fn from_linktype(linktype: pcap::Linktype) -> Result<DataLink, pcap::Linktype> {
        match linktype {
            pcap::Linktype(1) => {
                // LINKTYPE_ETHERNET
                Ok(DataLink::Ethernet)
            },
            pcap::Linktype(12) => {
                // RAW IP (linux tun)
                Ok(DataLink::Tun)
            },
            pcap::Linktype(127) => {
                // LINKTYPE_IEEE802_11_RADIOTAP
                Ok(DataLink::RadioTap)
            },
            x => Err(x),
        }
    }
}

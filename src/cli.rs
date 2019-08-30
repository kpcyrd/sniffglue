use structopt::clap::AppSettings;

#[derive(Debug, StructOpt)]
#[structopt(global_settings = &[AppSettings::ColoredHelp])]
pub struct Args {
    /// Set device to promisc
    #[structopt(short="p", long="promisc")]
    pub promisc: bool,
    /// Detailed output
    #[structopt(short="d", long="detailed")]
    pub detailed: bool,
    /// Json output (unstable)
    #[structopt(short="j", long="json")]
    pub json: bool,
    /// Show more packets (maximum: 4)
    #[structopt(short="v", long="verbose",
                parse(from_occurrences))]
    pub verbose: u8,
    /// Open device as pcap file
    #[structopt(short="r", long="read")]
    pub read: bool,
    /// Number of cores
    #[structopt(short="n", long="cpus")]
    pub cpus: Option<usize>,
    /// Device for sniffing
    pub device: Option<String>,
}

use clap::ArgAction;
use clap_complete::Shell;

#[derive(Debug, clap::Parser)]
#[allow(clippy::struct_excessive_bools)]
pub struct Args {
    /// Set device to promiscuous mode
    #[arg(short='p', long="promisc")]
    pub promisc: bool,
    /// Show fully dissected packets with all headers for development
    #[arg(long="debugging")]
    pub debugging: bool,
    /// Json output (unstable)
    #[arg(short='j', long="json")]
    pub json: bool,
    #[arg(short='v', long="verbose",
                action(ArgAction::Count),
                help="Increase filter sensitivity to show more (possibly less useful) packets.
The default only shows few packets, this flag can be specified multiple times. (maximum: 4)")]
    pub verbose: u8,
    /// Open a pcap file instead of a device
    #[arg(short='r', long="read")]
    pub read: bool,
    // --cpus is a legacy alias and going to be removed in the future
    /// Number of packet parsing threads (defaults to number of cpu cores)
    #[arg(short='n', long="threads", alias="cpus")]
    pub threads: Option<usize>,
    /// Disable syscall filter sandbox,
    /// this flag disables security features in sniffglue,
    /// please file a bug report if you need this option
    #[arg(long)]
    pub insecure_disable_seccomp: bool,
    /// Generate shell completions
    #[arg(long, hide=true)]
    pub gen_completions: Option<Shell>,
    /// The device or file to read packets from
    pub device: Option<String>,
}

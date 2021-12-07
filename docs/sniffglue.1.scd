sniffglue(1)

# NAME

sniffglue - secure multithreaded packet sniffer

# SYNOPSIS

*sniffglue [-vrpVh] [-n <threads>]* _device_

# DESCRIPTION

*sniffglue* is a network sniffer written in rust. Network packets are parsed
concurrently using a thread pool to utilize all cpu cores. Project goals are
that you can run *sniffglue* securely on untrusted networks and that it must
not crash when processing packets. The output should be as useful as possible
by default.

# OPTIONS

*-v*, *--verbose*
	Increase filter sensitivity to show more (possibly less useful) packets.
	The default only shows few packets, this flag can be specified multiple
	times. (maximum: 4)

*-h*, *--help*
	Prints help information.

*-p*, *--promisc*
	Set _device_ to promiscuous mode.

*-r*, *--read*
	Open _device_ as pcap file.

*-n*, *--threads* _threads_
	Specify the number of threads.

*-V*, *--version*
	Prints version information. If *-r* was specified, open as pcap file
	instead.

# EXAMPLES

Sniff with default filters (dhcp, dns, tls, http) from _enp0s25_:

	*sniffglue enp0s25*

Increase the filter sensitivity (arp):

	*sniffglue -v enp0s25*

Increase the filter sensitivity (cjdns, ssdp, dropbox, packets with valid utf8)

	*sniffglue -vv enp0s25*

Almost everything

	*sniffglue -vvv enp0s25*

Everything

	*sniffglue -vvvv enp0s25*

Read a dump from _sniff.pcap_, with increased filter sensitivity and decode packets with 1 thread:

	*sniffglue -vvrn1 sniff.pcap*

# PROTOCOLS

*ethernet*, *ipv4*, *ipv6*, *arp*, *tcp*, *udp*, *http*, *tls*, *dns*, *dhcp*,
*cjdns eth beacons*, *ssdp*, *dropbox beacons*

# SECURITY

To report a security issue please contact kpcyrd on ircs://irc.hackint.org.

## SECCOMP

To ensure a compromised process doesn't compromise the system, sniffglue uses
seccomp to restrict the syscalls that can be used after the process started.
This is done in two stages, first at the very beginning (directly after
env_logger initialized) and once after the sniffer has been setup, but before
packets are read from the network.

## HARDENING

During the second stage, there's also some general hardening that is applied
before all unneeded syscalls are finally disabled. Those are system specific,
so a configuration file is read from */etc/sniffglue.conf*. This config
file specifies an empty directory for *chroot* and an unprivileged account
in *user* that is used to drop root privileges.

## FUZZING

The packet processing of *sniffglue* can be fuzzed using _cargo-fuzz_.
Everything you should need is provided in the _fuzz/_ directory that is
distributed along with its source code. Please note that this program links
to _libpcap_ which is not included in the current fuzzing configuration.

# SEE ALSO

*pcap(3PCAP)*, *seccomp(2)*

# AUTHORS

This program was originally written and is currently maintained by kpcyrd.
Bug reports and patches are welcome on github:

	_https://github.com/kpcyrd/sniffglue_

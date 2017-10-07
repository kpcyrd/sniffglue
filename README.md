# sniffglue [![Build Status](https://travis-ci.org/kpcyrd/sniffglue.svg?branch=master)](https://travis-ci.org/kpcyrd/sniffglue) [![Crates.io](https://img.shields.io/crates/v/sniffglue.svg)](https://crates.io/crates/sniffglue)

Secure multithreaded packet sniffer.

## Usage

```
sniffglue --help
```

## Installation

Make sure you have libpcap and libseccomp installed:

Debian/Ubuntu:
```
apt-get install libpcap-dev libseccomp-dev
```

Archlinux:
```
pacman -S libpcap libseccomp
```

Install:
```
cargo install sniffglue
```

## Decoders

- [X] ethernet
- [X] ipv4
- [ ] ipv6
- [ ] arp
- [X] tcp
- [X] udp
- [ ] icmp
- [X] http
- [X] tls
- [ ] pop3
- [ ] smtp
- [ ] imap
- [X] dns
- [X] dhcp
- [ ] 802.11

## Security

sniffglue uses seccomp to restrict the syscalls that can be used after the process started. This is done in two stages, first at the very beginning (directly after env\_logger initialized) and once after the sniffer has been setup, but before packets are read from the network.

## Fuzzing

sniffglue supports cargo-fuzz. To start fuzzing, make sure [cargo-fuzz] is installed and run

```
cargo fuzz run read_packet
```

[cargo-fuzz]: https://github.com/rust-fuzz/cargo-fuzz

## License

GPLv3+

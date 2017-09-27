# sniffglue [![Build Status](https://travis-ci.org/kpcyrd/sniffglue-rs.svg?branch=master)](https://travis-ci.org/kpcyrd/sniffglue-rs) [![Crates.io](https://img.shields.io/crates/v/sniffglue.svg)](https://crates.io/crates/sniffglue)

Secure multithreaded packet sniffer.

## Usage

```
sniffglue --help
```

## Installation

Make sure you have libpcap installed:

Debian/Ubuntu:
```
apt-get install libpcap-dev
```

Archlinux:
```
pacman -S libpcap
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

## Fuzzing

sniffglue supports cargo-fuzz. To start fuzzing, make sure [cargo-fuzz] is installed and run

```
cargo fuzz run read_packet
```

[cargo-fuzz]: https://github.com/rust-fuzz/cargo-fuzz

## License

GPLv3+

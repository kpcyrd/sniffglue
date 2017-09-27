# sniffglue

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

## Fuzzing

sniffglue supports cargo-fuzz. To start fuzzing, make sure [cargo-fuzz] is installed and run

```
cargo fuzz run read_packet
```

[cargo-fuzz]: https://github.com/rust-fuzz/cargo-fuzz

## License

GPLv3+

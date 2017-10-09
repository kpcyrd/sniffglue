#!/bin/sh
set -ex

case "$BUILD_MODE" in
    release)
        RUST_LOG=sniffglue target/$TARGET/release/sniffglue -r pcaps/SkypeIRC.pcap > /dev/null
        ;;
    *)
        cargo test --verbose --target="$TARGET"
        ;;
esac

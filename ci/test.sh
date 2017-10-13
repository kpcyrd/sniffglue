#!/bin/sh
set -ex

case "$BUILD_MODE" in
    release)
        RUST_LOG=sniffglue target/$TARGET/release/sniffglue -r pcaps/SkypeIRC.pcap > /dev/null
        ;;
    docker)
        docker run -e RUST_LOG=sniffglue sniffglue --help
        ;;
    *)
        cargo test --verbose --target="$TARGET"
        ;;
esac

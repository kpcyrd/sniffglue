#!/bin/sh
set -x

case "$BUILD_MODE" in
    release)
        cargo build --verbose --release --target="$TARGET"
        ls -lah "target/$TARGET/release/sniffglue"
        file "target/$TARGET/release/sniffglue"
        ;;
    *)
        cargo build --verbose --target="$TARGET"
        ;;
esac

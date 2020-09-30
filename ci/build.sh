#!/bin/sh
set -ex

case "$BUILD_MODE" in
    release)
        cargo build --verbose --release --target="$TARGET"
        ls -lah "target/$TARGET/release/sniffglue"
        file "target/$TARGET/release/sniffglue"
        ;;
    boxxy)
        cargo build --verbose --examples
        ;;
    reprotest)
        docker build -t reprotest-sniffglue -f docs/Dockerfile.reprotest .
        ;;
esac

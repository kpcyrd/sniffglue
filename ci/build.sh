#!/bin/sh
set -ex

case "$BUILD_MODE" in
    release)
        cargo build --verbose --release --target="$TARGET"
        ls -lah "target/$TARGET/release/sniffglue"
        file "target/$TARGET/release/sniffglue"
        ;;
    docker)
        docker build -t sniffglue .
        docker images sniffglue
        ;;
    boxxy)
        cargo build --verbose --examples
        ;;
    reprotest)
        docker build -t reprotest-sniffglue -f ci/Dockerfile.reprotest .
        ;;
    *)
        cargo build --verbose --target="$TARGET"
        ;;
esac

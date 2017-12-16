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
        docker build -t reprotest-sniffglue -f docs/Dockerfile.reprotest .
        ;;
    musl)
        docker build -t musl-sniffglue -f docs/Dockerfile.musl .
        docker images musl-sniffglue
        ;;
    cross)
        docker build --build-arg TARGET="$TARGET" -t "sniffglue-test-$TARGET" -f ci/Dockerfile .
        # restart this script but inside the container and without BUILD_MODE=cross
        docker run -e TARGET="$TARGET" "sniffglue-test-$TARGET" ci/build.sh
        ;;
    *)
        cargo build --verbose --target="$TARGET"
        ;;
esac

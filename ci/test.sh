#!/bin/sh
set -ex

case "$BUILD_MODE" in
    release)
        # skip
        ;;
    *)
        cargo test --verbose --target="$TARGET"
        ;;
esac

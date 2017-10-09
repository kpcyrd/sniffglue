#!/bin/sh
set -x

case "$BUILD_MODE" in
    release)
        # skip
        ;;
    *)
        cargo test --verbose --target="$TARGET"
        ;;
esac

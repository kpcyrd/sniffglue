#!/bin/sh
set -xue
. /etc/os-release

export TMPDIR="$HOME/tmp/repro-test"
mkdir -p "$TMPDIR"

reprotest -vv --host-distro="$ID" --vary=-fileordering,-time --source-pattern 'Cargo.* src/' '
    RUSTC_BOOTSTRAP=1 CARGO_HOME="$PWD/.cargo" RUSTUP_HOME='"$HOME/.rustup"' \
        RUSTFLAGS="-Zremap-path-prefix-from=$HOME -Zremap-path-prefix-to=/remap-home -Zremap-path-prefix-from=$PWD -Zremap-path-prefix-to=/remap-pwd" \
        rustup run nightly cargo build --release --verbose' \
    target/release/sniffglue

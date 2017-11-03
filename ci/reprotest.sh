#!/bin/sh
set -xue
. /etc/os-release

export TMPDIR="$HOME/tmp/repro-test"
mkdir -p "$TMPDIR"

reprotest -vv --host-distro="$ID" --vary=-fileordering,-time,-home --source-pattern 'Cargo.* src/' '
    mkdir -p $HOME; ln -s '"$HOME/.rustup"' $HOME/.rustup;
    RUSTC_BOOTSTRAP=1 \
        CARGO_HOME="$PWD/.cargo" \
        RUSTFLAGS="-Zremap-path-prefix-from=$HOME -Zremap-path-prefix-to=/remap-home -Zremap-path-prefix-from=$PWD -Zremap-path-prefix-to=/remap-pwd" \
        rustup run nightly cargo build --release --verbose' \
    target/release/sniffglue

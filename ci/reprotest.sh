#!/bin/sh
set -xue
# we source /etc/os-release to detect the distro, after auto-detect[0] got released we
# can drop both `. /etc/os-release` and `--host-distro="$ID"`
# [0]: https://anonscm.debian.org/cgit/reproducible/reprotest.git/commit/?id=7e07ded787c5d16f172db6f1c12f1c1c02163405
. /etc/os-release

# by default, the build folder is located in /tmp, which is a tmpfs. The target/ folder
# can become quite large, causing the build to fail if we don't have enough RAM.
export TMPDIR="$HOME/tmp/repro-test"
mkdir -p "$TMPDIR"

reprotest -vv --host-distro="$ID" --vary=-time --source-pattern 'Cargo.* src/' '
    RUSTC_BOOTSTRAP=1 CARGO_HOME="$PWD/.cargo" RUSTUP_HOME='"$HOME/.rustup"' \
        RUSTFLAGS="-Zremap-path-prefix-from=$HOME -Zremap-path-prefix-to=/remap-home -Zremap-path-prefix-from=$PWD -Zremap-path-prefix-to=/remap-pwd" \
        rustup run nightly cargo build --release --verbose' \
    target/release/sniffglue

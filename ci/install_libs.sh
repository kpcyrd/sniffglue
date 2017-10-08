#!/bin/sh
set -x
apt-get -qq update
case "$1" in
    x86_64-unknown-linux-gnu)
        apt-get install -qy \
            libpcap-dev \
            libseccomp-dev
        ;;
    i686-unknown-linux-gnu)
        apt-get install -qy gcc-multilib \
            libpcap0.8-dev:i386 \
            libseccomp-dev:i386
        ;;
    *)
        echo "UNKNOWN TARGET: $TARGET"
        exit 1
        ;;
esac

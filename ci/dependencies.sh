#!/bin/sh
set -ex

if [ -z "$TRAVIS" ]; then
    case "$1" in
        aarch64-unknown-linux-gnu)
            dpkg --add-architecture arm64
            ;;
        i686-unknown-linux-gnu)
            dpkg --add-architecture i386
            ;;
    esac
fi

apt-get -q update

if [ -n "$TRAVIS" ]; then
    # update docker
    apt-get -y -o Dpkg::Options::="--force-confnew" install docker-ce
fi

case "$1" in
    x86_64-unknown-linux-gnu)
        apt-get install -qy \
            libpcap-dev \
            libseccomp-dev
        ;;
    aarch64-unknown-linux-gnu)
        if [ -z "$TRAVIS" ]; then
            apt-get install -qy gcc-6-aarch64-linux-gnu \
                libpcap0.8-dev:arm64 \
                libseccomp-dev:arm64
        fi
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

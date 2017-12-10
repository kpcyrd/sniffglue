#!/bin/sh
set -ex

case "$1" in
    arm-unknown-linux-gnueabihf)
        dpkg --add-architecture armhf
        ;;
esac

apt-get -qq update

# update docker
apt-get -y -o Dpkg::Options::="--force-confnew" install docker-ce

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
    arm-unknown-linux-gnueabihf)
        apt-get install -qy gcc-multilib \
            libpcap0.8-dev:armhf \
            libseccomp-dev:armhf
        ;;
    *)
        echo "UNKNOWN TARGET: $TARGET"
        exit 1
        ;;
esac

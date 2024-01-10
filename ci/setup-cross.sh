#!/bin/sh
set -xe

case "$1" in
    arm-*)
        ARCH=arm64
        ;;
    armv7-*)
        ARCH=arm64
        ;;
    aarch64-*)
        ARCH=arm64
        ;;
    i686-*)
        ARCH=i386
        ;;
    *)
        echo 'ERROR: unknown arch'
        exit 1
        ;;
esac

CROSS=`cross -V | sed -nr 's/cross (.*)/\1/p'`

cat > Dockerfile.cross <<EOF
FROM rustembedded/cross:$1-$CROSS
RUN dpkg --add-architecture $ARCH && \
    apt-get update && \
    apt-get install libpcap-dev:$ARCH libseccomp-dev:$ARCH
EOF

docker build -t "rustembedded/cross:$1-$CROSS" Dockerfile.cross

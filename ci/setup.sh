#!/bin/sh
set -ex

case "$1" in
    linux)
        apt-get -q update

        if [ -n "$TRAVIS" ]; then
            # update docker
            apt-get -y -o Dpkg::Options::="--force-confnew" install docker-ce
        fi

        apt-get install -qy \
            libpcap-dev \
            libseccomp-dev
        ;;
esac

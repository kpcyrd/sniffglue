FROM rust:alpine3.11
RUN apk add build-base libpcap-dev libseccomp-dev
WORKDIR /usr/src/sniffglue
COPY . .
RUN RUSTFLAGS="-C target-feature=-crt-static" cargo build --release --verbose \
    && strip target/release/sniffglue

FROM alpine:3.11
RUN apk add libgcc libpcap libseccomp
COPY docs/sniffglue.docker.conf /etc/sniffglue.conf
COPY --from=0 /usr/src/sniffglue/target/release/sniffglue /usr/local/bin/sniffglue
ENTRYPOINT ["/usr/local/bin/sniffglue"]

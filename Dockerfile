FROM rust:latest
RUN apt-get update -qq \
    && apt-get install -yq libpcap-dev libseccomp-dev
WORKDIR /usr/src/sniffglue
COPY . .
RUN cargo build --release
FROM busybox:1-glibc
COPY --from=0 /usr/src/sniffglue/target/release/sniffglue /usr/local/bin/sniffglue
COPY --from=0 /usr/lib/x86_64-linux-gnu/libpcap.so.0.8 /usr/lib/x86_64-linux-gnu/libpcap.so.0.8
COPY --from=0 /lib/x86_64-linux-gnu/libseccomp.so.2 \
    /lib/x86_64-linux-gnu/libdl.so.2 \
    /lib/x86_64-linux-gnu/librt.so.1 \
    /lib/x86_64-linux-gnu/libgcc_s.so.1 \
    /lib/x86_64-linux-gnu/
ENTRYPOINT ["sniffglue"]

FROM alpine:edge
RUN apk --no-cache add rust cargo libpcap-dev libseccomp-dev
WORKDIR /usr/src/sniffglue
COPY . .
RUN cargo build --release
FROM alpine:edge
RUN apk add --no-cache libpcap libseccomp libgcc
COPY --from=0 /usr/src/sniffglue/target/release/sniffglue /usr/local/bin/sniffglue
COPY docs/sniffglue.busybox.conf /etc/sniffglue.conf
ENTRYPOINT ["sniffglue"]

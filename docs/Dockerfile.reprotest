FROM debian:testing
RUN apt-get update -qq \
    && DEBIAN_FRONTEND=noninteractive apt-get upgrade -yq \
    && DEBIAN_FRONTEND=noninteractive apt-get install -yq --no-install-recommends diffoscope \
    && DEBIAN_FRONTEND=noninteractive apt-get install -yq reprotest \
    && DEBIAN_FRONTEND=noninteractive apt-get install -yq build-essential git curl libpcap-dev libseccomp-dev
ENV PYTHONIOENCODING=utf-8
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain nightly \
    && cp ~/.cargo/bin/rustup ~/.cargo/bin/cargo ~/.cargo/bin/rustc /usr/bin/
WORKDIR /sniffglue/
COPY . .

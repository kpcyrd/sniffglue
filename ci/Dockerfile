FROM rust:latest
ARG TARGET
WORKDIR /app
COPY . .
RUN rustup install "stable-$TARGET" \
    && rustup target add "$TARGET"
RUN ci/setup.sh linux

# build stage
FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

# runtime stage
FROM debian:bookworm-slim
COPY --from=build /src/target/release/identity-proxy /usr/local/bin/identity-proxy
USER proxy
EXPOSE 8443 8081
ENTRYPOINT ["identity-proxy"]

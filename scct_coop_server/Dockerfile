# Multi-stage build for a minimal Linux container
FROM rust:1.85-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /app
COPY . .

RUN cargo build --release -p scct_coop_server

FROM alpine:latest

WORKDIR /app
COPY --from=builder /app/target/release/scct_coop_server /app/scct_coop_server

EXPOSE 3478/udp
EXPOSE 8080/tcp

ENV RUST_LOG=info
ENV STUN_PORT=3478
ENV HTTP_PORT=8080

ENTRYPOINT ["/app/scct_coop_server"]

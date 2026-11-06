# Splinter Cell: Chaos Theory — Enhanced Coop

---

## Technical docs

This _SCCT Enhanced Coop_ mod consists of two parts:

1. **`scct_coop_server`**: A lightweight RFC 5389 STUN server and Axum HTTP signaling rendezvous server. Used for room code pairing and NAT hole-punching.
2. **`scct_coop_enhancer`**: The cross-platform desktop GUI launcher that handles mod installation, game launch, STUN hole-punching, in-memory runtime hooks.

### SCCT Coop Enhancer

...

### SCCT Coop Server

The `scct_coop_server` is needed to match friend codes and perform STUN. Without one, you can only play on LAN. I host an `scct_coop_server` at scct_coop.sholtrop.dev, completely free to use. The `scct_coop_enhancer` uses that one by default, but you can use a different one in "Advanced Server Configuration" in the GUI. Of course, you must use the same `scct_coop_server` as the person you're connecting to.

#### Self-hosting

You are free to host your own `scct_coop_server`. There are [Docker images here](https://github.com/sholtrop/scct_enhanced_coop/pkgs/container/scct_coop_server), or you can pull the latest:

```
docker pull ghcr.io/sholtrop/scct_coop_server:latest
```

designed to be run behind a reverse-proxy that can terminate TLS for you.

#### Security

- There's a default limit of 10k sessions, configurable via env var.
- Automated Banning: IPs that generate a lot of 404s might be trying to enumerate friend codes. By default, if an IP generates 100 invalid room lookups within 60 seconds, it is automatically banned for 15 minutes.
- Rate limiting: a per-IP rate limit of 10 req/s is enforced, configurable via env var.

---

#### Configuration

| Environment Variable    | Default Value | Description                                                                            | Recommendation                                                   |
| :---------------------- | :------------ | :------------------------------------------------------------------------------------- | :--------------------------------------------------------------- |
| `HTTP_PORT`             | `8080`        | TCP port the Axum signaling server listens on.                                         | Keep `8080` and reverse-proxy to `443` with TLS.                 |
| `STUN_PORT`             | `3478`        | UDP port the RFC 5389 STUN server listens on.                                          | Expose directly as `3478/udp` (STUN requires raw UDP).           |
| `MAX_SESSIONS`          | `10000`       | Maximum number of active concurrent pairing sessions allowed.                          | Set based on host RAM (~100–200 bytes per session).              |
| `SESSION_TTL_SECS`      | `900`         | Time (in seconds) an inactive session remains before being pruned (15 min).            |                                                                  |
| `CLEANUP_INTERVAL_SECS` | `60`          | Frequency (in seconds) of the background pruning task.                                 |                                                                  |
| `RATE_LIMIT_RPS`        | `10`          | Maximum HTTP requests allowed per second per IP address.                               | 10 req/s easily accommodates room polling while stopping floods. |
| `BAN_404_THRESHOLD`     | `100`         | Number of 404 responses an IP can accumulate before triggering an automatic ban.       |                                                                  |
| `BAN_404_WINDOW_SECS`   | `60`          | Time window (in seconds) for tracking 404 responses.                                   |                                                                  |
| `BAN_DURATION_SECS`     | `900`         | Duration (in seconds) an IP remains banned after exceeding the 404 threshold (15 min). |                                                                  |
| `RUST_LOG`              | `info`        | Global log filter (`error`, `warn`, `info`, `debug`, `trace`).                         | Use `info` in production; switch to `debug` for troubleshooting. |

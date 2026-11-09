# Splinter Cell: Chaos Theory — Enhanced Coop

Mod for Splinter Cell: Chaos Theory that let's you:

1. Play all single player levels in coop mode, in addition to standard coop levels.
2. Play over internet. No longer requires LAN or virtual LANs like Hamachi/ZeroTier. You and your friend join each other with a 5-character friend code.

Mod is 100% free and open source. You must have a valid copy of Splinter Cell Chaos Theory for it to work, e.g. via Steam.

## How to use

1. (Both) download the latest SCCT Coop Enhancer version from [the releases](https://github.com/sholtrop/scct_enhanced_coop/releases). E.g.
   `scct_coop_enhancer-<version>.exe`.

2. (Both) Run the executable. You will get a Windows Defender warning about this being a trojan. That is expected; Windows Defender is over-eager. If this happens, you will have to exempt this .exe in Windows Defender.

If you do not trust the .exe, upload the it to [VirusTotal](https://www.virustotal.com/gui/home/upload) and you'll see only one vendor (SecureAge) complaining.

3. (Both) You will see this UI: [public/images/coop_mod_ui.png]. Locate your Splinter Cell Chaos Theory installation. Note, the SCCT Coop Enhancer auto-locates common installation locations, such as Steam, but you can find it manually if you want another one.

4. (Both) Click the "Install Mod" button

5. One of you must click "Host Game". That person will get a 5-character friend code.

6. The other person must enter this friend code under "Join a Friend" and click "Join Game". You should now both see that you are connected.

7. (Both) Click "Launch Game"

8. In game, go to Coop -> Enhanced Coop. One of you can create a game (doesn't matter which one) and the other can join.

## FAQ

### Q: Does this work on Linux?

A: Binary releases are available for Linux, but I have **not** tested this on Linux under `wine` or Proton, etc.

## Technical docs

This _SCCT Enhanced Coop_ mod consists of two parts:

1. **`scct_coop_server`**: A lightweight RFC 5389 STUN server and Axum HTTP signaling rendezvous server. Used for room code pairing and NAT hole-punching.
2. **`scct_coop_enhancer`**: A desktop GUI launcher that handles mod installation, game launch, STUN hole-punching, in-memory runtime hooks.

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

## License

MIT

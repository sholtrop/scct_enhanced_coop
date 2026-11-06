mod api;
mod config;
mod registry;
mod security;
mod stun;

use config::Config;
use registry::FriendCodeRegistry;
use security::SecurityManager;
use std::time::Duration;
use stun::{MessageType, StunMessage};
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    log::info!("=== Splinter Cell: Chaos Theory — Coop Rendezvous & STUN Server ===");

    let config = Config::from_env();
    log::info!(
        "Configuration: HTTP port={}, STUN port={}, Max sessions={}, TTL={}s, Rate limit={} req/s, 404 Ban threshold={}/{}s",
        config.http_port,
        config.stun_port,
        config.max_sessions,
        config.session_ttl_secs,
        config.rate_limit_rps,
        config.ban_404_threshold,
        config.ban_404_window_secs
    );

    let stun_bind = format!("0.0.0.0:{}", config.stun_port);
    let http_bind = format!("0.0.0.0:{}", config.http_port);

    let registry = FriendCodeRegistry::new(config.max_sessions);
    let security = SecurityManager::new(
        config.rate_limit_rps,
        config.ban_404_threshold,
        Duration::from_secs(config.ban_404_window_secs),
        Duration::from_secs(config.ban_duration_secs),
    );

    // 1. Start STUN UDP Listener
    let stun_socket = UdpSocket::bind(&stun_bind).await?;
    log::info!("RFC 5389 STUN server listening on udp://{}", stun_bind);

    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let (n, peer) = match stun_socket.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(e) => {
                    log::error!("STUN recv_from error: {e}");
                    continue;
                }
            };

            match StunMessage::decode(&buf[..n]) {
                Ok(Some((_, msg))) if msg.msg_type == MessageType::BindingRequest => {
                    log::trace!(
                        "STUN BindingRequest from {} (len={} bytes) -> Mapped to {}",
                        peer,
                        n,
                        peer
                    );
                    let resp = StunMessage::binding_response(&msg, peer);
                    if let Ok(encoded) = resp.encode()
                        && let Err(e) = stun_socket.send_to(&encoded, peer).await
                    {
                        log::warn!("Failed to send STUN binding response to {peer}: {e}");
                    }
                }
                Ok(Some((_, msg))) => {
                    log::debug!(
                        "Received non-binding STUN message type {:?} from {} (len={})",
                        msg.msg_type,
                        peer,
                        n
                    );
                }
                Ok(None) => {
                    log::trace!("Received non-STUN / partial packet from {} (len={})", peer, n);
                }
                Err(e) => {
                    log::debug!("Failed to decode STUN packet from {} (len={}): {e}", peer, n);
                }
            }
        }
    });

    // 2. Start Background Cleanup Task
    let reg_cleanup = registry.clone();
    let sec_cleanup = security.clone();
    let cleanup_interval = Duration::from_secs(config.cleanup_interval_secs);
    let session_ttl = Duration::from_secs(config.session_ttl_secs);

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(cleanup_interval);
        loop {
            interval.tick().await;
            reg_cleanup.cleanup_expired(session_ttl);
            sec_cleanup.cleanup_expired();
        }
    });

    // 3. Run Signaling HTTP Server
    api::run_api_server(&http_bind, registry, security).await?;

    Ok(())
}

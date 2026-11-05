mod api;
mod registry;
mod stun;

use registry::FriendCodeRegistry;
use std::env;
use std::time::Duration;
use stun::{MessageType, StunMessage};
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Splinter Cell: Chaos Theory — Coop Rendezvous & STUN Server ===");

    let stun_port = env::var("STUN_PORT").unwrap_or_else(|_| "3478".to_string());
    let http_port = env::var("HTTP_PORT").unwrap_or_else(|_| "8080".to_string());

    let stun_bind = format!("0.0.0.0:{}", stun_port);
    let http_bind = format!("0.0.0.0:{}", http_port);

    let registry = FriendCodeRegistry::new();

    // 1. Start STUN UDP Listener
    let stun_socket = UdpSocket::bind(&stun_bind).await?;
    println!("  [STUN] RFC 5389 server listening on udp://{}", stun_bind);

    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let (n, peer) = match stun_socket.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("  [STUN] Recv error: {e}");
                    continue;
                }
            };

            if let Ok(Some((_, msg))) = StunMessage::decode(&buf[..n])
                && msg.msg_type == MessageType::BindingRequest
            {
                let resp = StunMessage::binding_response(&msg, peer);
                if let Ok(encoded) = resp.encode() {
                    let _ = stun_socket.send_to(&encoded, peer).await;
                }
            }
        }
    });

    // 2. Start Background Cleanup Task (sessions expire after 15 minutes)
    let reg_cleanup = registry.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            reg_cleanup.cleanup_expired(Duration::from_secs(900)).await;
        }
    });

    // 3. Run Signaling HTTP Server
    api::run_api_server(&http_bind, registry).await?;

    Ok(())
}

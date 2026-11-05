mod api;
mod registry;
mod stun;

use registry::FriendCodeRegistry;
use std::env;
use std::time::{Duration, SystemTime};
use stun::{MessageType, StunMessage};
use tokio::net::UdpSocket;

pub fn now_str() -> String {
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    format!("{:02}:{:02}:{:02}.{:03}", h, m, s, dur.subsec_millis())
}

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
                    eprintln!("  [STUN] [{}] Recv error from socket: {e}", now_str());
                    continue;
                }
            };

            match StunMessage::decode(&buf[..n]) {
                Ok(Some((_, msg))) if msg.msg_type == MessageType::BindingRequest => {
                    let tx_hex = msg
                        .txn_id
                        .0
                        .iter()
                        .map(|b| format!("{:02X}", b))
                        .collect::<String>();
                    println!(
                        "  [STUN] [{}] BindingRequest from {} (len={} bytes, tx_id={}) -> Mapped to {}",
                        now_str(),
                        peer,
                        n,
                        tx_hex,
                        peer
                    );
                    let resp = StunMessage::binding_response(&msg, peer);
                    if let Ok(encoded) = resp.encode()
                        && let Err(e) = stun_socket.send_to(&encoded, peer).await
                    {
                        eprintln!(
                            "  [STUN] [{}] Failed to send binding response to {peer}: {e}",
                            now_str()
                        );
                    }
                }
                Ok(Some((_, msg))) => {
                    println!(
                        "  [STUN] [{}] Received other STUN message type {:?} from {} (len={})",
                        now_str(),
                        msg.msg_type,
                        peer,
                        n
                    );
                }
                Ok(None) => {
                    println!(
                        "  [STUN] [{}] Received non-STUN / partial packet from {} (len={})",
                        now_str(),
                        peer,
                        n
                    );
                }
                Err(e) => {
                    println!(
                        "  [STUN] [{}] Failed to decode STUN packet from {} (len={}): {e}",
                        now_str(),
                        peer,
                        n
                    );
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

use crate::registry::{ClientEndpoints, FriendCodeRegistry};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub friend_code: Option<String>,
    pub disco_addr: SocketAddr,
    pub game_addr: SocketAddr,
    #[serde(default)]
    pub local_ip: Option<Ipv4Addr>,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub status: String,
    pub friend_code: String,
}

#[derive(Debug, Deserialize)]
pub struct JoinRequest {
    pub friend_code: String,
    pub disco_addr: SocketAddr,
    pub game_addr: SocketAddr,
    #[serde(default)]
    pub local_ip: Option<Ipv4Addr>,
}

#[derive(Debug, Serialize)]
pub struct JoinResponse {
    pub status: String,
    pub peer_disco_addr: Option<SocketAddr>,
    pub peer_game_addr: Option<SocketAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_local_ip: Option<Ipv4Addr>,
}

#[derive(Debug, Serialize)]
pub struct PollResponse {
    pub status: String,
    pub peer_disco_addr: Option<SocketAddr>,
    pub peer_game_addr: Option<SocketAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_local_ip: Option<Ipv4Addr>,
}

pub async fn run_api_server(bind_addr: &str, registry: FriendCodeRegistry) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(bind_addr).await?;
    println!("  [API] Signaling server listening on http://{}", bind_addr);

    let reg = Arc::new(registry);
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("  [API] Accept error: {e}");
                continue;
            }
        };

        let reg_clone = reg.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, reg_clone).await {
                eprintln!("  [API] Connection error: {e}");
            }
        });
    }
}

async fn handle_connection(mut stream: TcpStream, registry: Arc<FriendCodeRegistry>) -> Result<(), Box<dyn std::error::Error>> {
    let peer_addr = stream.peer_addr().ok();
    let peer_str = peer_addr
        .map(|a| a.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let req_str = String::from_utf8_lossy(&buf[..n]);
    let mut lines = req_str.lines();
    let req_line = lines.next().unwrap_or("");
    let parts: Vec<&str> = req_line.split_whitespace().collect();
    if parts.len() < 2 {
        println!(
            "  [API] [{}] 400 Bad Request from {}: invalid request line {:?}",
            crate::now_str(),
            peer_str,
            req_line
        );
        send_response(&mut stream, 400, "Bad Request", "text/plain", b"Bad Request").await?;
        return Ok(());
    }

    let method = parts[0];
    let path = parts[1];

    let body = req_str.split("\r\n\r\n").nth(1).unwrap_or("");

    match (method, path) {
        ("GET", "/health") => {
            println!(
                "  [API] [{}] GET /health from {} -> 200 OK",
                crate::now_str(),
                peer_str
            );
            send_response(&mut stream, 200, "OK", "application/json", b"{\"status\":\"ok\"}").await?;
        }
        ("POST", "/api/register") => {
            println!(
                "  [API] [{}] POST /api/register from {} | Body: {}",
                crate::now_str(),
                peer_str,
                body.trim()
            );
            let req: RegisterRequest = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => {
                    println!(
                        "  [API] [{}] 400 Bad Request in /api/register from {}: {e}",
                        crate::now_str(),
                        peer_str
                    );
                    let err = format!("{{\"error\":\"{e}\"}}");
                    send_response(&mut stream, 400, "Bad Request", "application/json", err.as_bytes()).await?;
                    return Ok(());
                }
            };

            let code = req.friend_code.unwrap_or_default();
            let endpoints = ClientEndpoints {
                disco_addr: req.disco_addr,
                game_addr: req.game_addr,
                local_ip: req.local_ip,
            };

            let final_code = registry.register(code, endpoints.clone()).await;
            println!(
                "  [API] [{}] Registered Host: Code='{}', Peer WAN: disco={}, game={}, Local LAN: {:?} (from {})",
                crate::now_str(),
                final_code,
                endpoints.disco_addr,
                endpoints.game_addr,
                endpoints.local_ip,
                peer_str
            );
            let resp = RegisterResponse {
                status: "registered".to_string(),
                friend_code: final_code,
            };
            let json = serde_json::to_vec(&resp)?;
            send_response(&mut stream, 200, "OK", "application/json", &json).await?;
        }
        ("POST", "/api/join") => {
            println!(
                "  [API] [{}] POST /api/join from {} | Body: {}",
                crate::now_str(),
                peer_str,
                body.trim()
            );
            let req: JoinRequest = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => {
                    println!(
                        "  [API] [{}] 400 Bad Request in /api/join from {}: {e}",
                        crate::now_str(),
                        peer_str
                    );
                    let err = format!("{{\"error\":\"{e}\"}}");
                    send_response(&mut stream, 400, "Bad Request", "application/json", err.as_bytes()).await?;
                    return Ok(());
                }
            };

            let guest_endpoints = ClientEndpoints {
                disco_addr: req.disco_addr,
                game_addr: req.game_addr,
                local_ip: req.local_ip,
            };

            if let Some(host_endpoints) = registry.join(&req.friend_code, guest_endpoints.clone()).await {
                println!(
                    "  [API] [{}] >>> MATCH PAIRED! Code='{}' <<<\n\
                     \x20       HOST:  WAN disco={}, game={}, Local LAN={:?}\n\
                     \x20       GUEST: WAN disco={}, game={}, Local LAN={:?} (Guest from {})",
                    crate::now_str(),
                    req.friend_code,
                    host_endpoints.disco_addr,
                    host_endpoints.game_addr,
                    host_endpoints.local_ip,
                    guest_endpoints.disco_addr,
                    guest_endpoints.game_addr,
                    guest_endpoints.local_ip,
                    peer_str
                );
                let resp = JoinResponse {
                    status: "paired".to_string(),
                    peer_disco_addr: Some(host_endpoints.disco_addr),
                    peer_game_addr: Some(host_endpoints.game_addr),
                    peer_local_ip: host_endpoints.local_ip,
                };
                let json = serde_json::to_vec(&resp)?;
                send_response(&mut stream, 200, "OK", "application/json", &json).await?;
            } else {
                println!(
                    "  [API] [{}] /api/join FAILED for code='{}': not found or expired (from {})",
                    crate::now_str(),
                    req.friend_code,
                    peer_str
                );
                let resp = JoinResponse {
                    status: "code_not_found".to_string(),
                    peer_disco_addr: None,
                    peer_game_addr: None,
                    peer_local_ip: None,
                };
                let json = serde_json::to_vec(&resp)?;
                send_response(&mut stream, 404, "Not Found", "application/json", &json).await?;
            }
        }
        ("GET", p) if p.starts_with("/api/poll/") => {
            let code = &p["/api/poll/".len()..];
            if let Some(guest_endpoints) = registry.poll(code).await {
                println!(
                    "  [API] [{}] Host polled code='{}' -> GUEST IS READY! Returning Guest WAN: disco={}, game={}, LAN: {:?} (to host {})",
                    crate::now_str(),
                    code,
                    guest_endpoints.disco_addr,
                    guest_endpoints.game_addr,
                    guest_endpoints.local_ip,
                    peer_str
                );
                let resp = PollResponse {
                    status: "paired".to_string(),
                    peer_disco_addr: Some(guest_endpoints.disco_addr),
                    peer_game_addr: Some(guest_endpoints.game_addr),
                    peer_local_ip: guest_endpoints.local_ip,
                };
                let json = serde_json::to_vec(&resp)?;
                send_response(&mut stream, 200, "OK", "application/json", &json).await?;
            } else if registry.lookup(code).await.is_some() {
                println!(
                    "  [API] [{}] Host polled code='{}' -> still waiting for guest (host {})",
                    crate::now_str(),
                    code,
                    peer_str
                );
                let resp = PollResponse {
                    status: "waiting".to_string(),
                    peer_disco_addr: None,
                    peer_game_addr: None,
                    peer_local_ip: None,
                };
                let json = serde_json::to_vec(&resp)?;
                send_response(&mut stream, 200, "OK", "application/json", &json).await?;
            } else {
                println!(
                    "  [API] [{}] Host polled code='{}' -> code not found / expired (from {})",
                    crate::now_str(),
                    code,
                    peer_str
                );
                let resp = PollResponse {
                    status: "code_not_found".to_string(),
                    peer_disco_addr: None,
                    peer_game_addr: None,
                    peer_local_ip: None,
                };
                let json = serde_json::to_vec(&resp)?;
                send_response(&mut stream, 404, "Not Found", "application/json", &json).await?;
            }
        }
        _ => {
            println!(
                "  [API] [{}] 404 Not Found: {} {} from {}",
                crate::now_str(),
                method,
                path,
                peer_str
            );
            send_response(&mut stream, 404, "Not Found", "text/plain", b"404 Not Found").await?;
        }
    }

    Ok(())
}

async fn send_response(stream: &mut TcpStream, status_code: u16, status_text: &str, content_type: &str, body: &[u8]) -> Result<(), std::io::Error> {
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
        status_code, status_text, content_type, body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

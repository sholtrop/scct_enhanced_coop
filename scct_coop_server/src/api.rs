use crate::registry::{ClientEndpoints, FriendCodeRegistry};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub friend_code: Option<String>,
    pub disco_addr: SocketAddr,
    pub game_addr: SocketAddr,
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
}

#[derive(Debug, Serialize)]
pub struct JoinResponse {
    pub status: String,
    pub peer_disco_addr: Option<SocketAddr>,
    pub peer_game_addr: Option<SocketAddr>,
}

#[derive(Debug, Serialize)]
pub struct PollResponse {
    pub status: String,
    pub peer_disco_addr: Option<SocketAddr>,
    pub peer_game_addr: Option<SocketAddr>,
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
        send_response(&mut stream, 400, "Bad Request", "text/plain", b"Bad Request").await?;
        return Ok(());
    }

    let method = parts[0];
    let path = parts[1];

    let body = req_str.split("\r\n\r\n").nth(1).unwrap_or("");

    match (method, path) {
        ("GET", "/health") => {
            send_response(&mut stream, 200, "OK", "application/json", b"{\"status\":\"ok\"}").await?;
        }
        ("POST", "/api/register") => {
            let req: RegisterRequest = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => {
                    let err = format!("{{\"error\":\"{e}\"}}");
                    send_response(&mut stream, 400, "Bad Request", "application/json", err.as_bytes()).await?;
                    return Ok(());
                }
            };

            let code = req.friend_code.unwrap_or_default();
            let endpoints = ClientEndpoints {
                disco_addr: req.disco_addr,
                game_addr: req.game_addr,
            };

            let final_code = registry.register(code, endpoints).await;
            let resp = RegisterResponse {
                status: "registered".to_string(),
                friend_code: final_code,
            };
            let json = serde_json::to_vec(&resp)?;
            send_response(&mut stream, 200, "OK", "application/json", &json).await?;
        }
        ("POST", "/api/join") => {
            let req: JoinRequest = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => {
                    let err = format!("{{\"error\":\"{e}\"}}");
                    send_response(&mut stream, 400, "Bad Request", "application/json", err.as_bytes()).await?;
                    return Ok(());
                }
            };

            let guest_endpoints = ClientEndpoints {
                disco_addr: req.disco_addr,
                game_addr: req.game_addr,
            };

            if let Some(host_endpoints) = registry.join(&req.friend_code, guest_endpoints).await {
                let resp = JoinResponse {
                    status: "paired".to_string(),
                    peer_disco_addr: Some(host_endpoints.disco_addr),
                    peer_game_addr: Some(host_endpoints.game_addr),
                };
                let json = serde_json::to_vec(&resp)?;
                send_response(&mut stream, 200, "OK", "application/json", &json).await?;
            } else {
                let resp = JoinResponse {
                    status: "code_not_found".to_string(),
                    peer_disco_addr: None,
                    peer_game_addr: None,
                };
                let json = serde_json::to_vec(&resp)?;
                send_response(&mut stream, 404, "Not Found", "application/json", &json).await?;
            }
        }
        ("GET", p) if p.starts_with("/api/poll/") => {
            let code = &p["/api/poll/".len()..];
            if let Some(guest_endpoints) = registry.poll(code).await {
                let resp = PollResponse {
                    status: "paired".to_string(),
                    peer_disco_addr: Some(guest_endpoints.disco_addr),
                    peer_game_addr: Some(guest_endpoints.game_addr),
                };
                let json = serde_json::to_vec(&resp)?;
                send_response(&mut stream, 200, "OK", "application/json", &json).await?;
            } else if registry.lookup(code).await.is_some() {
                let resp = PollResponse {
                    status: "waiting".to_string(),
                    peer_disco_addr: None,
                    peer_game_addr: None,
                };
                let json = serde_json::to_vec(&resp)?;
                send_response(&mut stream, 200, "OK", "application/json", &json).await?;
            } else {
                let resp = PollResponse {
                    status: "code_not_found".to_string(),
                    peer_disco_addr: None,
                    peer_game_addr: None,
                };
                let json = serde_json::to_vec(&resp)?;
                send_response(&mut stream, 404, "Not Found", "application/json", &json).await?;
            }
        }
        _ => {
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

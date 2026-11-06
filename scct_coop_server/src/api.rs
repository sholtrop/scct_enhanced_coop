use axum::{
    extract::{ConnectInfo, Extension, Path, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tower_http::cors::CorsLayer;
use tower_http::timeout::TimeoutLayer;

use crate::registry::{
    ClientEndpoints, FriendCodeRegistry, JoinResult, PollResult, RegisterResult,
};
use crate::security::SecurityManager;

pub struct AppState {
    pub registry: FriendCodeRegistry,
    pub security: SecurityManager,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub friend_code: Option<String>,
    pub disco_addr: SocketAddr,
    pub game_addr: SocketAddr,
    #[serde(default)]
    pub local_ip: Option<Ipv4Addr>,
}

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct JoinResponse {
    pub status: String,
    pub peer_disco_addr: Option<SocketAddr>,
    pub peer_game_addr: Option<SocketAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_local_ip: Option<Ipv4Addr>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PollResponse {
    pub status: String,
    pub peer_disco_addr: Option<SocketAddr>,
    pub peer_game_addr: Option<SocketAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_local_ip: Option<Ipv4Addr>,
}

pub fn extract_client_ip(headers: &HeaderMap, peer_addr: Option<SocketAddr>) -> IpAddr {
    // 1. Cloudflare header
    if let Some(cf) = headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
    {
        return cf;
    }
    // 2. Standard X-Forwarded-For (take the first IP in the chain)
    if let Some(ip) = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|xff| xff.split(',').next())
        .and_then(|first| first.trim().parse::<IpAddr>().ok())
    {
        return ip;
    }
    // 3. X-Real-IP
    if let Some(xrip) = headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
    {
        return xrip;
    }
    // 4. Socket peer address fallback
    peer_addr
        .map(|a| a.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
}

async fn security_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Response {
    let peer_addr = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0);
    let client_ip = extract_client_ip(req.headers(), peer_addr);
    req.extensions_mut().insert(client_ip);

    // 1. Check if IP is banned
    if state.security.is_banned(&client_ip) {
        log::warn!("Rejected request from banned IP: {}", client_ip);
        return (
            StatusCode::FORBIDDEN,
            [("Content-Type", "application/json")],
            r#"{"error":"IP is temporarily banned due to excessive invalid requests"}"#,
        )
            .into_response();
    }

    // 2. Check rate limit
    if !state.security.check_rate_limit(&client_ip) {
        log::debug!("Rate limit exceeded for IP: {}", client_ip);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [
                ("Retry-After", "1"),
                ("Content-Type", "application/json"),
            ],
            r#"{"error":"Rate limit exceeded. Maximum 10 requests per second."}"#,
        )
            .into_response();
    }

    // 3. Run inner request handler
    let resp = next.run(req).await;

    // 4. Record 404 response if applicable
    if resp.status() == StatusCode::NOT_FOUND {
        state.security.record_404(&client_ip);
    }

    resp
}

async fn health_handler() -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::OK, Json(serde_json::json!({ "status": "ok" })))
}

async fn register_handler(
    State(state): State<Arc<AppState>>,
    Extension(client_ip): Extension<IpAddr>,
    Json(req): Json<RegisterRequest>,
) -> Response {
    let endpoints = ClientEndpoints {
        disco_addr: req.disco_addr,
        game_addr: req.game_addr,
        local_ip: req.local_ip,
    };
    let requested_code = req.friend_code.unwrap_or_default();

    match state.registry.register(requested_code, endpoints.clone()) {
        RegisterResult::Success(code) => {
            log::info!(
                "Registered Host: Code='{}', Peer WAN: disco={}, game={}, Local LAN: {:?} (from {})",
                code,
                endpoints.disco_addr,
                endpoints.game_addr,
                endpoints.local_ip,
                client_ip
            );
            (
                StatusCode::OK,
                Json(RegisterResponse {
                    status: "registered".to_string(),
                    friend_code: code,
                }),
            )
                .into_response()
        }
        RegisterResult::AlreadyConnected => {
            log::warn!(
                "Registration rejected for host {}: friend code is already connected",
                client_ip
            );
            (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "status": "already_connected",
                    "error": "Session is already connected and cannot be overwritten"
                })),
            )
                .into_response()
        }
        RegisterResult::CapacityExceeded => {
            log::warn!(
                "Registration rejected for {}: server session capacity reached ({})",
                client_ip,
                state.registry.active_count()
            );
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "status": "capacity_exceeded",
                    "error": "Server has reached maximum active session capacity"
                })),
            )
                .into_response()
        }
    }
}

async fn join_handler(
    State(state): State<Arc<AppState>>,
    Extension(client_ip): Extension<IpAddr>,
    Json(req): Json<JoinRequest>,
) -> Response {
    let guest_endpoints = ClientEndpoints {
        disco_addr: req.disco_addr,
        game_addr: req.game_addr,
        local_ip: req.local_ip,
    };

    match state
        .registry
        .join(&req.friend_code, guest_endpoints.clone())
    {
        JoinResult::Success(host_endpoints) => {
            log::info!(
                ">>> MATCH PAIRED! Code='{}' <<<\n\
                 \x20    HOST:  WAN disco={}, game={}, Local LAN={:?}\n\
                 \x20    GUEST: WAN disco={}, game={}, Local LAN={:?} (Guest from {})",
                req.friend_code,
                host_endpoints.disco_addr,
                host_endpoints.game_addr,
                host_endpoints.local_ip,
                guest_endpoints.disco_addr,
                guest_endpoints.game_addr,
                guest_endpoints.local_ip,
                client_ip
            );
            (
                StatusCode::OK,
                Json(JoinResponse {
                    status: "paired".to_string(),
                    peer_disco_addr: Some(host_endpoints.disco_addr),
                    peer_game_addr: Some(host_endpoints.game_addr),
                    peer_local_ip: host_endpoints.local_ip,
                }),
            )
                .into_response()
        }
        JoinResult::AlreadyConnected => {
            log::warn!(
                "Join rejected for code='{}' from {}: session is already paired/connected",
                req.friend_code,
                client_ip
            );
            (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "status": "already_connected",
                    "error": "Session is already connected"
                })),
            )
                .into_response()
        }
        JoinResult::NotFound => {
            log::debug!(
                "/api/join code='{}' not found from {}",
                req.friend_code,
                client_ip
            );
            (
                StatusCode::NOT_FOUND,
                Json(JoinResponse {
                    status: "code_not_found".to_string(),
                    peer_disco_addr: None,
                    peer_game_addr: None,
                    peer_local_ip: None,
                }),
            )
                .into_response()
        }
    }
}

async fn poll_handler(
    State(state): State<Arc<AppState>>,
    Extension(client_ip): Extension<IpAddr>,
    Path(code): Path<String>,
) -> Response {

    match state.registry.poll(&code) {
        PollResult::Paired(guest) => {
            log::debug!(
                "Host polled code='{}' -> guest is ready (host {})",
                code,
                client_ip
            );
            (
                StatusCode::OK,
                Json(PollResponse {
                    status: "paired".to_string(),
                    peer_disco_addr: Some(guest.disco_addr),
                    peer_game_addr: Some(guest.game_addr),
                    peer_local_ip: guest.local_ip,
                }),
            )
                .into_response()
        }
        PollResult::Waiting => {
            log::trace!("Host polled code='{}' -> waiting (host {})", code, client_ip);
            (
                StatusCode::OK,
                Json(PollResponse {
                    status: "waiting".to_string(),
                    peer_disco_addr: None,
                    peer_game_addr: None,
                    peer_local_ip: None,
                }),
            )
                .into_response()
        }
        PollResult::NotFound => {
            log::trace!(
                "Host polled code='{}' -> not found / expired (from {})",
                code,
                client_ip
            );
            (
                StatusCode::NOT_FOUND,
                Json(PollResponse {
                    status: "code_not_found".to_string(),
                    peer_disco_addr: None,
                    peer_game_addr: None,
                    peer_local_ip: None,
                }),
            )
                .into_response()
        }
    }
}

pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/api/register", post(register_handler))
        .route("/api/join", post(join_handler))
        .route("/api/poll/{code}", get(poll_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security_middleware,
        ))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(15),
        ))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

pub async fn run_api_server(
    bind_addr: &str,
    registry: FriendCodeRegistry,
    security: SecurityManager,
) -> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(AppState { registry, security });
    let app = create_router(state);

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    log::info!("Signaling server listening on http://{}", bind_addr);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use tower::ServiceExt;

    fn test_app() -> (Router, Arc<AppState>) {
        let registry = FriendCodeRegistry::new(100);
        let security = SecurityManager::new(
            10,
            5, // lower threshold for 404 test
            Duration::from_secs(60),
            Duration::from_secs(60),
        );
        let state = Arc::new(AppState { registry, security });
        (create_router(state.clone()), state)
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let (app, _) = test_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ok");
    }

    #[tokio::test]
    async fn test_register_and_poll_flow() {
        let (app, _) = test_app();

        // 1. Register host
        let reg_payload = serde_json::json!({
            "friend_code": "MATCH",
            "disco_addr": "1.2.3.4:9100",
            "game_addr": "1.2.3.4:9103",
            "local_ip": "192.168.1.10"
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/register")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&reg_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let reg_resp: RegisterResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(reg_resp.friend_code, "MATCH");

        // 2. Host poll -> waiting
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/poll/MATCH")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let poll_resp: PollResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(poll_resp.status, "waiting");

        // 3. Guest joins
        let join_payload = serde_json::json!({
            "friend_code": "MATCH",
            "disco_addr": "5.6.7.8:9100",
            "game_addr": "5.6.7.8:9103",
            "local_ip": "192.168.1.20"
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/join")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&join_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let join_resp: JoinResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(join_resp.status, "paired");
        assert_eq!(
            join_resp.peer_disco_addr,
            Some("1.2.3.4:9100".parse().unwrap())
        );

        // 4. Host poll -> paired
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/poll/MATCH")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let poll_resp: PollResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(poll_resp.status, "paired");
        assert_eq!(
            poll_resp.peer_disco_addr,
            Some("5.6.7.8:9100".parse().unwrap())
        );

        // 5. Overwrite protection: second guest cannot join connected session
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/join")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&join_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);

        // 6. Overwrite protection: cannot re-register connected session
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/register")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&reg_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_rate_limit_and_ban() {
        let (app, _) = test_app();

        // Send 10 valid requests
        for _ in 0..10 {
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/health")
                        .header("x-forwarded-for", "203.0.113.1")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }

        // 11th request from same IP within the second -> 429
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .header("x-forwarded-for", "203.0.113.1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

        // Another IP is not rate-limited
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .header("x-forwarded-for", "203.0.113.2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Test 404 accumulation and automatic ban
        // In test_app, ban_404_threshold is set to 5
        let scan_ip = "198.51.100.55";
        for _ in 0..5 {
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/poll/NONEX")
                        .header("x-forwarded-for", scan_ip)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        }

        // 6th request from scan_ip -> banned (403 Forbidden)
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .header("x-forwarded-for", scan_ip)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}

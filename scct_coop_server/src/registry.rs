use rand::{rng, Rng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Crockford Base32 alphabet (32 characters, excludes I, L, O, U to avoid ambiguity)
pub const CROCKFORD_CHARS: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub fn generate_friend_code() -> String {
    let mut code = String::with_capacity(5);
    let mut r = rng();
    for _ in 0..5 {
        let idx = r.random_range(0..CROCKFORD_CHARS.len());
        code.push(CROCKFORD_CHARS[idx] as char);
    }
    code
}

pub fn normalize_friend_code(input: &str) -> String {
    input
        .trim()
        .to_ascii_uppercase()
        .chars()
        .filter_map(|c| match c {
            'O' => Some('0'),
            'I' | 'L' => Some('1'),
            c if CROCKFORD_CHARS.contains(&(c as u8)) => Some(c),
            _ => None,
        })
        .take(5)
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientEndpoints {
    pub disco_addr: SocketAddr,
    pub game_addr: SocketAddr,
    #[serde(default)]
    pub local_ip: Option<Ipv4Addr>,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Session {
    pub friend_code: String,
    pub host_endpoints: ClientEndpoints,
    pub guest_endpoints: Option<ClientEndpoints>,
    pub created_at: Instant,
    pub last_seen: Instant,
}

#[derive(Debug, Clone)]
pub struct FriendCodeRegistry {
    sessions: Arc<RwLock<HashMap<String, Session>>>,
}

impl Default for FriendCodeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl FriendCodeRegistry {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn register(&self, friend_code: String, host_endpoints: ClientEndpoints) -> String {
        let code = normalize_friend_code(&friend_code);
        let final_code = if code.len() == 5 {
            code
        } else {
            generate_friend_code()
        };

        let now = Instant::now();
        let session = Session {
            friend_code: final_code.clone(),
            host_endpoints,
            guest_endpoints: None,
            created_at: now,
            last_seen: now,
        };

        let mut lock = self.sessions.write().await;
        lock.insert(final_code.clone(), session);
        final_code
    }

    pub async fn lookup(&self, friend_code: &str) -> Option<Session> {
        let code = normalize_friend_code(friend_code);
        let lock = self.sessions.read().await;
        lock.get(&code).cloned()
    }

    pub async fn join(&self, friend_code: &str, guest_endpoints: ClientEndpoints) -> Option<ClientEndpoints> {
        let code = normalize_friend_code(friend_code);
        let mut lock = self.sessions.write().await;
        if let Some(session) = lock.get_mut(&code) {
            session.guest_endpoints = Some(guest_endpoints);
            session.last_seen = Instant::now();
            Some(session.host_endpoints.clone())
        } else {
            None
        }
    }

    pub async fn poll(&self, friend_code: &str) -> Option<ClientEndpoints> {
        let code = normalize_friend_code(friend_code);
        let mut lock = self.sessions.write().await;
        if let Some(session) = lock.get_mut(&code) {
            session.last_seen = Instant::now();
            session.guest_endpoints.clone()
        } else {
            None
        }
    }

    pub async fn cleanup_expired(&self, ttl: Duration) {
        let now = Instant::now();
        let mut lock = self.sessions.write().await;
        lock.retain(|_, s| now.duration_since(s.last_seen) < ttl);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_friend_code_generator() {
        let code = generate_friend_code();
        assert_eq!(code.len(), 5);
        for b in code.bytes() {
            assert!(CROCKFORD_CHARS.contains(&b));
        }
    }

    #[test]
    fn test_normalize_friend_code() {
        assert_eq!(normalize_friend_code("k7x9b"), "K7X9B");
        assert_eq!(normalize_friend_code("o1li"), "0111");
    }

    #[tokio::test]
    async fn test_registry_pairing() {
        let registry = FriendCodeRegistry::new();
        let host_ep = ClientEndpoints {
            disco_addr: "1.2.3.4:9100".parse().unwrap(),
            game_addr: "1.2.3.4:9103".parse().unwrap(),
            local_ip: Some(Ipv4Addr::new(192, 168, 1, 10)),
        };
        let guest_ep = ClientEndpoints {
            disco_addr: "5.6.7.8:9100".parse().unwrap(),
            game_addr: "5.6.7.8:9103".parse().unwrap(),
            local_ip: Some(Ipv4Addr::new(192, 168, 1, 20)),
        };

        let code = registry.register("K7X9B".to_string(), host_ep.clone()).await;
        assert_eq!(code, "K7X9B");

        // Before guest joins, poll returns None
        assert_eq!(registry.poll(&code).await, None);

        // Guest joins with code
        let host_received = registry.join(&code, guest_ep.clone()).await;
        assert_eq!(host_received, Some(host_ep));

        // After guest joins, host poll returns guest endpoints
        assert_eq!(registry.poll(&code).await, Some(guest_ep));
    }
}

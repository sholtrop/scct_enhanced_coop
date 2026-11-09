use dashmap::DashMap;
use rand::{rng, Rng};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

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

#[derive(Debug, Clone)]
pub struct Session {
    pub host_endpoints: ClientEndpoints,
    pub guest_endpoints: Option<ClientEndpoints>,
    pub last_seen: Instant,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RegisterResult {
    Success(String),
    AlreadyConnected,
    CapacityExceeded,
}

#[derive(Debug, PartialEq, Eq)]
pub enum JoinResult {
    Success(ClientEndpoints),
    AlreadyConnected,
    NotFound,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PollResult {
    Paired(ClientEndpoints),
    Waiting,
    NotFound,
}

#[derive(Debug, Clone)]
pub struct FriendCodeRegistry {
    sessions: Arc<DashMap<String, Session>>,
    max_sessions: usize,
}

impl FriendCodeRegistry {
    pub fn new(max_sessions: usize) -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            max_sessions,
        }
    }

    /// Register a host session.
    /// If the requested friend code is already active and connected, returns `AlreadyConnected`.
    /// If total active sessions exceeds `max_sessions`, returns `CapacityExceeded`.
    pub fn register(&self, friend_code: String, host_endpoints: ClientEndpoints) -> RegisterResult {
        let code = normalize_friend_code(&friend_code);
        let final_code = if code.len() == 5 {
            code
        } else {
            if self.sessions.len() >= self.max_sessions {
                return RegisterResult::CapacityExceeded;
            }
            let mut candidate = generate_friend_code();
            let mut attempts = 0;
            while self.sessions.contains_key(&candidate) && attempts < 100 {
                candidate = generate_friend_code();
                attempts += 1;
            }
            candidate
        };

        // If code already exists, ensure it is not already connected
        if let Some(existing) = self.sessions.get(&final_code) {
            if existing.guest_endpoints.is_some() {
                return RegisterResult::AlreadyConnected;
            }
        } else if self.sessions.len() >= self.max_sessions {
            return RegisterResult::CapacityExceeded;
        }

        let now = Instant::now();
        let session = Session {
            host_endpoints,
            guest_endpoints: None,
            last_seen: now,
        };

        self.sessions.insert(final_code.clone(), session);
        RegisterResult::Success(final_code)
    }

    /// Guest attempts to join a room.
    /// If session already has a guest connected, returns `AlreadyConnected` to prevent overwriting.
    pub fn join(&self, friend_code: &str, guest_endpoints: ClientEndpoints) -> JoinResult {
        let code = normalize_friend_code(friend_code);
        if let Some(mut session) = self.sessions.get_mut(&code) {
            if session.guest_endpoints.is_some() {
                JoinResult::AlreadyConnected
            } else {
                session.guest_endpoints = Some(guest_endpoints);
                session.last_seen = Instant::now();
                JoinResult::Success(session.host_endpoints.clone())
            }
        } else {
            JoinResult::NotFound
        }
    }

    /// Host polls for guest arrival.
    pub fn poll(&self, friend_code: &str) -> PollResult {
        let code = normalize_friend_code(friend_code);
        if let Some(mut session) = self.sessions.get_mut(&code) {
            session.last_seen = Instant::now();
            if let Some(guest) = &session.guest_endpoints {
                PollResult::Paired(guest.clone())
            } else {
                PollResult::Waiting
            }
        } else {
            PollResult::NotFound
        }
    }

    /// Clean up expired sessions based on last_seen time.
    pub fn cleanup_expired(&self, ttl: Duration) -> usize {
        let now = Instant::now();
        let before = self.sessions.len();
        self.sessions.retain(|code, s| {
            let keep = now.duration_since(s.last_seen) < ttl;
            if !keep {
                log::debug!("Friend code '{}' expired and removed", code);
            }
            keep
        });
        let removed = before - self.sessions.len();
        if removed > 0 {
            log::info!(
                "Pruned {} expired session(s). Active sessions: {}",
                removed,
                self.sessions.len()
            );
        }
        removed
    }

    pub fn active_count(&self) -> usize {
        self.sessions.len()
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

    #[test]
    fn test_registry_pairing() {
        let registry = FriendCodeRegistry::new(100);
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

        let res = registry.register("K7X9B".to_string(), host_ep.clone());
        assert_eq!(res, RegisterResult::Success("K7X9B".to_string()));

        // Before guest joins, poll returns Waiting
        assert_eq!(registry.poll("K7X9B"), PollResult::Waiting);

        // Guest joins with code
        let join_res = registry.join("K7X9B", guest_ep.clone());
        assert_eq!(join_res, JoinResult::Success(host_ep.clone()));

        // After guest joins, host poll returns guest endpoints
        assert_eq!(registry.poll("K7X9B"), PollResult::Paired(guest_ep.clone()));

        // Second guest attempting to join fails with AlreadyConnected
        let second_guest = registry.join("K7X9B", guest_ep.clone());
        assert_eq!(second_guest, JoinResult::AlreadyConnected);

        // Re-registering connected code fails with AlreadyConnected
        let re_reg = registry.register("K7X9B".to_string(), host_ep.clone());
        assert_eq!(re_reg, RegisterResult::AlreadyConnected);
    }

    #[test]
    fn test_capacity_limit() {
        let registry = FriendCodeRegistry::new(2);
        let ep = ClientEndpoints {
            disco_addr: "1.2.3.4:9100".parse().unwrap(),
            game_addr: "1.2.3.4:9103".parse().unwrap(),
            local_ip: None,
        };

        assert!(matches!(
            registry.register("AAAAA".to_string(), ep.clone()),
            RegisterResult::Success(_)
        ));
        assert!(matches!(
            registry.register("BBBBB".to_string(), ep.clone()),
            RegisterResult::Success(_)
        ));
        assert_eq!(
            registry.register("CCCCC".to_string(), ep.clone()),
            RegisterResult::CapacityExceeded
        );
    }
}

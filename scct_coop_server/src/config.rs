use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub http_port: u16,
    pub stun_port: u16,
    pub max_sessions: usize,
    pub session_ttl_secs: u64,
    pub cleanup_interval_secs: u64,
    pub rate_limit_rps: u32,
    pub ban_404_threshold: u32,
    pub ban_404_window_secs: u64,
    pub ban_duration_secs: u64,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            http_port: env_u16("HTTP_PORT", 8080),
            stun_port: env_u16("STUN_PORT", 3478),
            max_sessions: env_usize("MAX_SESSIONS", 10_000),
            session_ttl_secs: env_u64("SESSION_TTL_SECS", 900),
            cleanup_interval_secs: env_u64("CLEANUP_INTERVAL_SECS", 60),
            rate_limit_rps: env_u32("RATE_LIMIT_RPS", 10),
            ban_404_threshold: env_u32("BAN_404_THRESHOLD", 100),
            ban_404_window_secs: env_u64("BAN_404_WINDOW_SECS", 60),
            ban_duration_secs: env_u64("BAN_DURATION_SECS", 900),
        }
    }
}

fn env_u16(key: &str, default: u16) -> u16 {
    env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<u16>().ok())
        .unwrap_or(default)
}

fn env_u32(key: &str, default: u32) -> u32 {
    env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(default)
}

fn env_u64(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_usize(key: &str, default: usize) -> usize {
    env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(default)
}


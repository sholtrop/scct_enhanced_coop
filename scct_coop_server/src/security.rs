use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct RateLimitBucket {
    second: u64,
    count: u32,
}

#[derive(Clone)]
pub struct SecurityManager {
    rate_limits: Arc<DashMap<IpAddr, RateLimitBucket>>,
    not_found_history: Arc<DashMap<IpAddr, Vec<Instant>>>,
    banned_ips: Arc<DashMap<IpAddr, Instant>>,

    rate_limit_rps: u32,
    ban_404_threshold: u32,
    ban_404_window: Duration,
    ban_duration: Duration,
}

impl SecurityManager {
    pub fn new(
        rate_limit_rps: u32,
        ban_404_threshold: u32,
        ban_404_window: Duration,
        ban_duration: Duration,
    ) -> Self {
        Self {
            rate_limits: Arc::new(DashMap::new()),
            not_found_history: Arc::new(DashMap::new()),
            banned_ips: Arc::new(DashMap::new()),
            rate_limit_rps,
            ban_404_threshold,
            ban_404_window,
            ban_duration,
        }
    }

    /// Check whether an IP is currently banned. If a past ban has expired, it is removed.
    pub fn is_banned(&self, ip: &IpAddr) -> bool {
        if let Some(expiry) = self.banned_ips.get(ip) {
            if Instant::now() < *expiry {
                true
            } else {
                drop(expiry);
                self.banned_ips.remove(ip);
                false
            }
        } else {
            false
        }
    }

    /// Check rate limit (10 req/s per IP). Returns true if request is allowed, false if limit exceeded.
    pub fn check_rate_limit(&self, ip: &IpAddr) -> bool {
        let current_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut entry = self.rate_limits.entry(*ip).or_insert(RateLimitBucket {
            second: current_sec,
            count: 0,
        });

        if entry.second == current_sec {
            entry.count += 1;
            entry.count <= self.rate_limit_rps
        } else {
            entry.second = current_sec;
            entry.count = 1;
            true
        }
    }

    /// Record a 404 response for this IP. If threshold is exceeded in the window, bans the IP.
    pub fn record_404(&self, ip: &IpAddr) {
        let now = Instant::now();
        let mut history = self.not_found_history.entry(*ip).or_default();
        history.push(now);
        history.retain(|t| now.duration_since(*t) < self.ban_404_window);

        if history.len() >= self.ban_404_threshold as usize {
            let ban_until = now + self.ban_duration;
            self.banned_ips.insert(*ip, ban_until);
            log::warn!(
                "SECURITY: IP {} banned for {:?}: exceeded {} 404s within {:?}",
                ip,
                self.ban_duration,
                self.ban_404_threshold,
                self.ban_404_window
            );
            history.clear();
        }
    }

    /// Clean up stale buckets and expired bans.
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        let current_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Prune rate limits older than 5 seconds
        self.rate_limits
            .retain(|_, b| current_sec.saturating_sub(b.second) < 5);

        // Prune empty or aged-out 404 histories
        self.not_found_history.retain(|_, v| {
            v.retain(|t| now.duration_since(*t) < self.ban_404_window);
            !v.is_empty()
        });

        // Prune expired bans
        self.banned_ips.retain(|_, expiry| now < *expiry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter() {
        let sec = SecurityManager::new(
            3,
            10,
            Duration::from_secs(60),
            Duration::from_secs(60),
        );
        let ip: IpAddr = "192.168.1.100".parse().unwrap();

        assert!(sec.check_rate_limit(&ip));
        assert!(sec.check_rate_limit(&ip));
        assert!(sec.check_rate_limit(&ip));
        assert!(!sec.check_rate_limit(&ip)); // 4th request in same second fails
    }

    #[test]
    fn test_404_ban() {
        let sec = SecurityManager::new(
            100,
            5,
            Duration::from_secs(60),
            Duration::from_secs(60),
        );
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        assert!(!sec.is_banned(&ip));
        for _ in 0..4 {
            sec.record_404(&ip);
            assert!(!sec.is_banned(&ip));
        }
        // 5th 404 triggers ban
        sec.record_404(&ip);
        assert!(sec.is_banned(&ip));
    }
}


//! Rate limits for authentication endpoints (docs/02 §7).

use std::{net::IpAddr, num::NonZeroU32, time::Duration};

use governor::{
    DefaultKeyedRateLimiter, Quota, RateLimiter,
    clock::{Clock, DefaultClock},
};

use crate::error::ApiError;

const fn nz(n: u32) -> NonZeroU32 {
    match NonZeroU32::new(n) {
        Some(v) => v,
        None => panic!("zero quota"),
    }
}

#[derive(Debug)]
pub struct Limiters {
    /// login / unlock / recovery per source IP: 10/min, burst 5.
    pub auth_ip: DefaultKeyedRateLimiter<IpAddr>,
    /// login / unlock / recovery per username: 5 per 15 min.
    pub auth_user: DefaultKeyedRateLimiter<String>,
    /// invite redemption and first-run setup per IP: 5/min.
    pub enroll_ip: DefaultKeyedRateLimiter<IpAddr>,
}

impl Default for Limiters {
    fn default() -> Self {
        Self {
            auth_ip: RateLimiter::keyed(Quota::per_minute(nz(10)).allow_burst(nz(5))),
            auth_user: RateLimiter::keyed(
                Quota::with_period(Duration::from_secs(180))
                    .map_or_else(|| Quota::per_minute(nz(1)), |q| q.allow_burst(nz(5))),
            ),
            enroll_ip: RateLimiter::keyed(Quota::per_minute(nz(5))),
        }
    }
}

fn check<K: std::hash::Hash + Eq + Clone>(
    lim: &DefaultKeyedRateLimiter<K>,
    key: &K,
) -> Result<(), ApiError> {
    lim.check_key(key)
        .map_err(|not_until| ApiError::RateLimited {
            retry_after_secs: not_until
                .wait_time_from(DefaultClock::default().now())
                .as_secs()
                + 1,
        })
}

impl Limiters {
    /// IP limit first (cheap, bounds key growth), then the per-username limit.
    pub fn check_auth(&self, ip: IpAddr, username: &str) -> Result<(), ApiError> {
        check(&self.auth_ip, &ip)?;
        check(&self.auth_user, &username.to_lowercase())
    }

    pub fn check_enroll(&self, ip: IpAddr) -> Result<(), ApiError> {
        check(&self.enroll_ip, &ip)
    }

    pub fn housekeeping(&self) {
        self.auth_ip.retain_recent();
        self.auth_user.retain_recent();
        self.enroll_ip.retain_recent();
    }
}

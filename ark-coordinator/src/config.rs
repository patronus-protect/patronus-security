// SPDX-License-Identifier: GPL-3.0-only
use serde::Deserialize;
use std::{
    collections::HashSet,
    net::SocketAddr,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorConfig {
    pub server: ServerConfig,
    pub auth: CoordinatorAuthConfig,
    pub gateway: GatewayConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub bind: SocketAddr,
    #[serde(default = "default_max_upload_mb")]
    pub max_upload_mb: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorAuthConfig {
    pub keys: Vec<CoordinatorApiKey>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorApiKey {
    pub key_hash: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    pub redis_url_file: PathBuf,
    pub cube_token_file: PathBuf,
    pub cubes: Vec<Cube>,
    #[serde(default = "default_redis_prefix")]
    pub redis_prefix: String,
    #[serde(default = "default_retention_secs")]
    pub retention_secs: u64,
    #[serde(default = "default_max_waiting_requests")]
    pub max_waiting_requests: usize,
    #[serde(default = "default_chunk_bytes")]
    pub chunk_bytes: usize,
    #[serde(default = "default_chunks_per_batch")]
    pub chunks_per_batch: usize,
    #[serde(default = "default_parent_deadline_ms")]
    pub parent_deadline_ms: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Cube {
    pub name: String,
    pub url: String,
    #[serde(default = "default_cube_slots")]
    pub max_in_flight: usize,
}

fn default_max_upload_mb() -> usize {
    2
}
fn default_redis_prefix() -> String {
    "ark:coordinator:v1:".into()
}
fn default_retention_secs() -> u64 {
    900
}
fn default_max_waiting_requests() -> usize {
    64
}
fn default_chunk_bytes() -> usize {
    4096
}
fn default_chunks_per_batch() -> usize {
    4
}
fn default_parent_deadline_ms() -> u64 {
    300_000
}
fn default_cube_slots() -> usize {
    3
}

impl CoordinatorConfig {
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let config: Self = serde_yaml::from_slice(&std::fs::read(path)?)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.auth.keys.is_empty()
            || self.auth.keys.iter().any(|key| {
                key.key_hash.len() != 64
                    || !key.key_hash.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        {
            return Err("auth.keys must contain SHA-256 hashes");
        }
        if self.server.max_upload_mb == 0
            || self.server.max_upload_mb > 1024
            || self.gateway.max_waiting_requests > 1024
            || self.gateway.retention_secs < 900
            || self.gateway.redis_prefix.is_empty()
            || self.gateway.chunk_bytes < 4
            || !(4..=8).contains(&self.gateway.chunks_per_batch)
            || !(1..=MAX_COORDINATOR_PARENT_DEADLINE_MS).contains(&self.gateway.parent_deadline_ms)
        {
            return Err("invalid coordinator limits or Redis retention");
        }
        if self.gateway.cubes.is_empty() {
            return Err("gateway.cubes must not be empty");
        }
        let admitted = self
            .gateway
            .cubes
            .iter()
            .try_fold(self.gateway.max_waiting_requests, |total, cube| {
                total.checked_add(cube.max_in_flight)
            });
        if admitted.is_none_or(|requests| requests > crate::fair_queue::MAX_REQUESTS) {
            return Err("coordinator admission must not exceed FairQueue capacity");
        }
        let buffered_mb = admitted.and_then(|slots| slots.checked_mul(self.server.max_upload_mb));
        if buffered_mb.is_none_or(|mb| mb > 512) {
            return Err("upload limit times admitted requests must not exceed 512 MiB");
        }
        let mut names = HashSet::new();
        let mut urls = HashSet::new();
        for cube in &self.gateway.cubes {
            let url = reqwest::Url::parse(&cube.url).map_err(|_| "invalid Cube URL")?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || url.path() != "/"
                || cube.name.trim().is_empty()
                || !names.insert(cube.name.as_str())
                || !urls.insert(cube.url.trim_end_matches('/'))
                || cube.max_in_flight != 3
            {
                return Err("Cubes need unique HTTP(S) origins and exactly three slots");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coordinator_config_requires_three_slots_per_cube() {
        let yaml = "server: { bind: '127.0.0.1:0' }\nauth: { keys: [{ key_hash: '0000000000000000000000000000000000000000000000000000000000000000' }] }\ngateway:\n  redis_url_file: redis.url\n  cube_token_file: cube.token\n  cubes: [{ name: a, url: 'http://cube.example', max_in_flight: 3 }]\n";
        let config: CoordinatorConfig = serde_yaml::from_str(yaml).unwrap();
        config.validate().unwrap();
        assert_eq!(config.server.max_upload_mb, 2);
        assert_eq!(config.gateway.chunk_bytes, 4096);
        assert_eq!(config.gateway.chunks_per_batch, 4);
        assert_eq!(config.gateway.parent_deadline_ms, 300_000);

        let mut invalid = config;
        invalid.gateway.cubes[0].max_in_flight = 2;
        assert!(invalid.validate().is_err());

        let mut excessive: CoordinatorConfig = serde_yaml::from_str(yaml).unwrap();
        excessive.server.max_upload_mb = 8;
        excessive.gateway.max_waiting_requests = 64;
        assert!(excessive.validate().unwrap_err().contains("512 MiB"));

        let mut queue_at_limit: CoordinatorConfig = serde_yaml::from_str(yaml).unwrap();
        queue_at_limit.gateway.max_waiting_requests = crate::fair_queue::MAX_REQUESTS - 3;
        queue_at_limit.validate().unwrap();

        let mut queue_overflow = queue_at_limit;
        queue_overflow.gateway.max_waiting_requests += 1;
        assert!(queue_overflow.validate().unwrap_err().contains("FairQueue"));
    }
}

// The shipped Compose service allows 310s for shutdown. Bound parent work to
// 300s plus 5s for draining/persistence, leaving 5s for process termination.
pub const MAX_COORDINATOR_PARENT_DEADLINE_MS: u64 = 300_000;
impl GatewayConfig {
    pub fn drain_timeout_ms(&self) -> Option<u64> {
        self.parent_deadline_ms.checked_add(5_000)
    }
}
#[cfg(test)]
mod runtime_limit_tests {
    use super::*;
    #[test]
    fn utf8_minimum_and_parent_deadline_fit_compose_shutdown_grace() {
        let yaml = "server: { bind: '127.0.0.1:0' }\nauth: { keys: [{ key_hash: '0000000000000000000000000000000000000000000000000000000000000000' }] }\ngateway:\n  redis_url_file: redis.url\n  cube_token_file: cube.token\n  cubes: [{ name: a, url: 'http://cube.example', max_in_flight: 3 }]\n";
        let mut config: CoordinatorConfig = serde_yaml::from_str(yaml).unwrap();
        for bytes in 0..4 {
            config.gateway.chunk_bytes = bytes;
            assert!(config.validate().is_err());
        }
        config.gateway.chunk_bytes = 4;
        config.gateway.parent_deadline_ms = MAX_COORDINATOR_PARENT_DEADLINE_MS;
        config.validate().unwrap();
        let compose: serde_yaml::Value =
            serde_yaml::from_str(include_str!("../deploy/compose.yaml")).unwrap();
        let grace = compose["services"]["coordinator"]["stop_grace_period"]
            .as_str()
            .unwrap()
            .strip_suffix('s')
            .unwrap()
            .parse::<u64>()
            .unwrap()
            * 1_000;
        assert!(config.gateway.drain_timeout_ms().unwrap() < grace);
        for deadline in [0, MAX_COORDINATOR_PARENT_DEADLINE_MS + 1, u64::MAX] {
            config.gateway.parent_deadline_ms = deadline;
            assert!(config.validate().is_err());
        }
        assert!(config.gateway.drain_timeout_ms().is_none());
    }
}

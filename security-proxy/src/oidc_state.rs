use dashmap::DashMap;
use std::time::{Duration, Instant};

pub struct OidcStateEntry {
    pub code_verifier: String,
    pub provider_key: String,
    created_at: Instant,
}

const TTL: Duration = Duration::from_secs(10 * 60); // 10 minutes

pub struct OidcStateStore {
    states: DashMap<String, OidcStateEntry>,
}

impl OidcStateStore {
    pub fn new() -> Self {
        Self {
            states: DashMap::new(),
        }
    }

    pub fn store(&self, state: String, code_verifier: String, provider_key: String) {
        self.states.insert(
            state,
            OidcStateEntry {
                code_verifier,
                provider_key,
                created_at: Instant::now(),
            },
        );
    }

    pub fn take(&self, state: &str) -> Option<OidcStateEntry> {
        self.states.remove(state).and_then(|(_, entry)| {
            if entry.created_at.elapsed() < TTL {
                Some(entry)
            } else {
                None
            }
        })
    }
}

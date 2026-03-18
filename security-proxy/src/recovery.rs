use dashmap::DashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct RecoveryEntry {
    pub flow_state: String,
    pub email: String,
    pub created_at: Instant,
}

#[derive(Debug, Clone)]
pub struct ResetEntry {
    /// Kratos identity UUID (= app users.id)
    pub user_id: String,
    pub created_at: Instant,
}

const TTL: Duration = Duration::from_secs(15 * 60); // 15 minutes

pub struct RecoveryStore {
    // recovery_token -> RecoveryEntry (stores Kratos action URL + email for code submission)
    recovery: DashMap<String, RecoveryEntry>,
    // reset_token -> ResetEntry (stores user id for password change via admin API)
    reset: DashMap<String, ResetEntry>,
}

impl RecoveryStore {
    pub fn new() -> Self {
        Self {
            recovery: DashMap::new(),
            reset: DashMap::new(),
        }
    }

    pub fn store_recovery(&self, token: String, flow_state: String, email: String) {
        self.recovery.insert(
            token,
            RecoveryEntry {
                flow_state,
                email,
                created_at: Instant::now(),
            },
        );
    }

    pub fn take_recovery(&self, token: &str) -> Option<RecoveryEntry> {
        self.recovery.remove(token).and_then(|(_, entry)| {
            if entry.created_at.elapsed() < TTL {
                Some(entry)
            } else {
                None
            }
        })
    }

    pub fn store_reset(&self, token: String, user_id: String) {
        self.reset.insert(
            token,
            ResetEntry {
                user_id,
                created_at: Instant::now(),
            },
        );
    }

    pub fn take_reset(&self, token: &str) -> Option<ResetEntry> {
        self.reset.remove(token).and_then(|(_, entry)| {
            if entry.created_at.elapsed() < TTL {
                Some(entry)
            } else {
                None
            }
        })
    }
}

use std::collections::HashMap;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct DecisionCacheKey {
    pub role_id: u32,
    pub resource: String,
    pub permission: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheEntry {
    pub decision: bool,
    pub expires_at: u64, // 0 = permanent, otherwise unix millis
}

#[derive(Debug, Clone)]
pub struct DecisionCache {
    entries: HashMap<DecisionCacheKey, CacheEntry>,
    capacity: usize,
}

impl DecisionCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity),
            capacity: capacity.max(1),
        }
    }

    pub fn get(&self, key: &DecisionCacheKey) -> Option<bool> {
        self.get_with_expiry(key, 0)
    }

    pub fn get_with_expiry(&self, key: &DecisionCacheKey, current_time: u64) -> Option<bool> {
        if let Some(entry) = self.entries.get(key) {
            if entry.expires_at == 0 || entry.expires_at > current_time {
                return Some(entry.decision);
            }
        }
        None
    }

    pub fn put(&mut self, key: DecisionCacheKey, decision: bool) {
        self.put_with_ttl(key, decision, 0, 0);
    }

    pub fn put_with_ttl(&mut self, key: DecisionCacheKey, decision: bool, ttl_ms: u64, current_time: u64) {
        let expires_at = if ttl_ms == 0 {
            0
        } else {
            current_time.saturating_add(ttl_ms)
        };

        if self.entries.len() >= self.capacity && !self.entries.contains_key(&key) {
            if let Some(first_key) = self.entries.keys().next().cloned() {
                self.entries.remove(&first_key);
            }
        }

        self.entries.insert(key, CacheEntry { decision, expires_at });
    }

    pub fn prune_expired(&mut self, current_time: u64) -> usize {
        let initial = self.entries.len();
        self.entries.retain(|_, v| v.expires_at == 0 || v.expires_at > current_time);
        initial - self.entries.len()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

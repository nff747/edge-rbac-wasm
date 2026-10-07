use std::collections::HashMap;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct DecisionCacheKey {
    pub role_id: u32,
    pub resource: String,
    pub permission: u32,
}

#[derive(Debug, Clone)]
pub struct DecisionCache {
    entries: HashMap<DecisionCacheKey, bool>,
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
        self.entries.get(key).copied()
    }

    pub fn put(&mut self, key: DecisionCacheKey, decision: bool) {
        if self.entries.len() >= self.capacity && !self.entries.contains_key(&key) {
            // Evict arbitrary entry to respect capacity
            if let Some(first_key) = self.entries.keys().next().cloned() {
                self.entries.remove(&first_key);
            }
        }
        self.entries.insert(key, decision);
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

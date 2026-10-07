use edge_rbac_wasm::cache::{DecisionCache, DecisionCacheKey};

#[test]
fn test_decision_cache_hit_and_miss() {
    let mut cache = DecisionCache::new(5);
    let key = DecisionCacheKey {
        role_id: 1,
        resource: "api:users".to_string(),
        permission: 1,
    };

    assert_eq!(cache.get(&key), None);
    cache.put(key.clone(), true);
    assert_eq!(cache.get(&key), Some(true));
}

#[test]
fn test_decision_cache_capacity_bound() {
    let mut cache = DecisionCache::new(2);
    for i in 0..5 {
        let key = DecisionCacheKey {
            role_id: i,
            resource: format!("res_{}", i),
            permission: 1,
        };
        cache.put(key, true);
    }
    assert!(cache.len() <= 2);
}

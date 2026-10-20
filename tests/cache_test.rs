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

#[test]
fn test_decision_cache_ttl_expiration_and_pruning() {
    let mut cache = DecisionCache::new(10);
    let key1 = DecisionCacheKey {
        role_id: 1,
        resource: "doc:1".to_string(),
        permission: 1,
    };
    let key2 = DecisionCacheKey {
        role_id: 2,
        resource: "doc:2".to_string(),
        permission: 1,
    };

    // key1 expires at t = 1000, key2 is permanent (ttl = 0)
    cache.put_with_ttl(key1.clone(), true, 500, 500); // expires at 1000
    cache.put_with_ttl(key2.clone(), false, 0, 500); // permanent

    // Before expiration (t = 800)
    assert_eq!(cache.get_with_expiry(&key1, 800), Some(true));
    assert_eq!(cache.get_with_expiry(&key2, 800), Some(false));

    // After expiration (t = 1200)
    assert_eq!(cache.get_with_expiry(&key1, 1200), None);
    assert_eq!(cache.get_with_expiry(&key2, 1200), Some(false));

    // Prune expired entries at t = 1200
    let purged = cache.prune_expired(1200);
    assert_eq!(purged, 1);
    assert_eq!(cache.len(), 1);
}

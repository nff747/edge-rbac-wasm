use edge_rbac_wasm::engine::UnifiedEngine;
use edge_rbac_wasm::policy::{Effect, PolicyRule};
use edge_rbac_wasm::resource::ResourcePattern;
use edge_rbac_wasm::bitflags::*;
use std::collections::HashMap;

#[test]
fn test_unified_engine_full_lifecycle() {
    let mut engine = UnifiedEngine::new(10);
    // Role 2 inherits Role 1
    engine.graph.add_edge(2, 1).unwrap();

    engine.policy.add_rule(PolicyRule {
        id: "r1".to_string(),
        effect: Effect::Allow,
        role_id: 1,
        resource: ResourcePattern::new("api:v1:public:*"),
        permissions: PERM_READ,
        conditions: Vec::new(),
    });

    let ctx = HashMap::new();
    // Same tenant, role 2 inheriting role 1 can read
    let (granted, audit) = engine.authorize(100, 2, 100, "api:v1:public:feed", PERM_READ, "req_1", &ctx);
    assert!(granted);
    assert_eq!(audit.granted, true);

    // Cross-tenant access denied
    let (cross_granted, cross_audit) = engine.authorize(100, 2, 999, "api:v1:public:feed", PERM_READ, "req_2", &ctx);
    assert!(!cross_granted);
    assert_eq!(cross_audit.reason, "Tenant boundary isolation violation");
}

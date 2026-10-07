use edge_rbac_wasm::policy::{Effect, PolicyDocument, PolicyRule};
use edge_rbac_wasm::resource::ResourcePattern;
use edge_rbac_wasm::bitflags::PERM_WRITE;
use std::collections::HashMap;

#[test]
fn test_allow_rule_evaluation() {
    let mut doc = PolicyDocument::new();
    doc.add_rule(PolicyRule {
        id: "rule_1".to_string(),
        effect: Effect::Allow,
        role_id: 2,
        resource: ResourcePattern::new("documents:*"),
        permissions: PERM_WRITE,
        conditions: Vec::new(),
    });

    let ctx = HashMap::new();
    let res = doc.evaluate(&[2], "documents:report_1", PERM_WRITE, &ctx);
    assert_eq!(res, Effect::Allow);
}

#[test]
fn test_explicit_deny_overrides_allow() {
    let mut doc = PolicyDocument::new();
    // Allow rule
    doc.add_rule(PolicyRule {
        id: "allow_rule".to_string(),
        effect: Effect::Allow,
        role_id: 2,
        resource: ResourcePattern::new("documents:**"),
        permissions: PERM_WRITE,
        conditions: Vec::new(),
    });
    // Explicit Deny rule on sensitive subpath
    doc.add_rule(PolicyRule {
        id: "deny_rule".to_string(),
        effect: Effect::Deny,
        role_id: 2,
        resource: ResourcePattern::new("documents:confidential:*"),
        permissions: PERM_WRITE,
        conditions: Vec::new(),
    });

    let ctx = HashMap::new();
    // Normal document is Allowed
    assert_eq!(doc.evaluate(&[2], "documents:public:report", PERM_WRITE, &ctx), Effect::Allow);
    // Confidential document is Denied
    assert_eq!(doc.evaluate(&[2], "documents:confidential:payroll", PERM_WRITE, &ctx), Effect::Deny);
}

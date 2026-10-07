use edge_rbac_wasm::validator::{PolicyValidator, ValidationWarning};
use edge_rbac_wasm::policy::{Effect, PolicyRule};
use edge_rbac_wasm::resource::ResourcePattern;

#[test]
fn test_validator_detects_zero_permission_and_empty_resource() {
    let rules = vec![
        PolicyRule {
            id: "bad_rule".to_string(),
            effect: Effect::Allow,
            role_id: 1,
            resource: ResourcePattern::new(""),
            permissions: 0,
            conditions: Vec::new(),
        }
    ];

    let warnings = PolicyValidator::validate_rules(&rules);
    assert_eq!(warnings.len(), 2);
    assert!(warnings.contains(&ValidationWarning::ZeroPermission("bad_rule".to_string())));
    assert!(warnings.contains(&ValidationWarning::EmptyResourcePattern("bad_rule".to_string())));
}

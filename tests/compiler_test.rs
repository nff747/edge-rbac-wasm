use edge_rbac_wasm::compiler::PolicyBinaryCodec;
use edge_rbac_wasm::policy::{Effect, PolicyRule};
use edge_rbac_wasm::resource::ResourcePattern;
use edge_rbac_wasm::bitflags::PERM_READ;

#[test]
fn test_encode_and_decode_rules() {
    let rules = vec![
        PolicyRule {
            id: "r1".to_string(),
            effect: Effect::Allow,
            role_id: 10,
            resource: ResourcePattern::new("api:v1:data:*"),
            permissions: PERM_READ,
            conditions: Vec::new(),
        },
        PolicyRule {
            id: "r2".to_string(),
            effect: Effect::Deny,
            role_id: 20,
            resource: ResourcePattern::new("admin:**"),
            permissions: 0xFF,
            conditions: Vec::new(),
        },
    ];

    let bytes = PolicyBinaryCodec::encode_rules(&rules);
    assert!(!bytes.is_empty());

    let decoded = PolicyBinaryCodec::decode_rules(&bytes).expect("Failed decoding");
    assert_eq!(decoded.len(), 2);
    assert_eq!(decoded[0].role_id, 10);
    assert_eq!(decoded[0].effect, Effect::Allow);
    assert_eq!(decoded[0].resource.raw(), "api:v1:data:*");

    assert_eq!(decoded[1].role_id, 20);
    assert_eq!(decoded[1].effect, Effect::Deny);
}

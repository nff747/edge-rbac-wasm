use edge_rbac_wasm::abac::{AttributeCondition, Operator};
use std::collections::HashMap;

#[test]
fn test_abac_equality_and_inequality() {
    let mut ctx = HashMap::new();
    ctx.insert("env".to_string(), "production".to_string());
    ctx.insert("role".to_string(), "engineer".to_string());

    let cond_eq = AttributeCondition::new("env", Operator::Equals, "production");
    assert!(cond_eq.evaluate(&ctx));

    let cond_neq = AttributeCondition::new("env", Operator::NotEquals, "staging");
    assert!(cond_neq.evaluate(&ctx));
}

#[test]
fn test_abac_set_membership() {
    let mut ctx = HashMap::new();
    ctx.insert("department".to_string(), "finance".to_string());

    let cond_in = AttributeCondition::new("department", Operator::In, "hr,finance,legal");
    assert!(cond_in.evaluate(&ctx));

    let cond_not_in = AttributeCondition::new("department", Operator::In, "sales,marketing");
    assert!(!cond_not_in.evaluate(&ctx));
}

#[test]
fn test_abac_numeric_comparison() {
    let mut ctx = HashMap::new();
    ctx.insert("clearance_level".to_string(), "5".to_string());

    let cond_gt = AttributeCondition::new("clearance_level", Operator::GreaterThan, "3");
    assert!(cond_gt.evaluate(&ctx));

    let cond_lt = AttributeCondition::new("clearance_level", Operator::LessThan, "2");
    assert!(!cond_lt.evaluate(&ctx));
}

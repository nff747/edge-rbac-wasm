use crate::policy::PolicyRule;
use std::collections::HashSet;

#[derive(Debug, PartialEq, Eq)]
pub enum ValidationWarning {
    ZeroPermission(String),
    EmptyResourcePattern(String),
    DuplicateRuleId(String),
}

pub struct PolicyValidator;

impl PolicyValidator {
    pub fn validate_rules(rules: &[PolicyRule]) -> Vec<ValidationWarning> {
        let mut warnings = Vec::new();
        let mut seen_ids = HashSet::new();

        for r in rules {
            if !seen_ids.insert(r.id.as_str()) {
                warnings.push(ValidationWarning::DuplicateRuleId(r.id.clone()));
            }
            if r.permissions == 0 {
                warnings.push(ValidationWarning::ZeroPermission(r.id.clone()));
            }
            if r.resource.raw().trim().is_empty() {
                warnings.push(ValidationWarning::EmptyResourcePattern(r.id.clone()));
            }
        }
        warnings
    }
}

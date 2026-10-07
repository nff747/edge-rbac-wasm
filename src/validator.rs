use crate::policy::PolicyRule;

#[derive(Debug, PartialEq, Eq)]
pub enum ValidationWarning {
    ZeroPermission(String),
    EmptyResourcePattern(String),
}

pub struct PolicyValidator;

impl PolicyValidator {
    pub fn validate_rules(rules: &[PolicyRule]) -> Vec<ValidationWarning> {
        let mut warnings = Vec::new();
        for r in rules {
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

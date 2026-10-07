use crate::resource::ResourcePattern;
use crate::abac::AttributeCondition;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Debug, Clone)]
pub struct PolicyRule {
    pub id: String,
    pub effect: Effect,
    pub role_id: u32,
    pub resource: ResourcePattern,
    pub permissions: u32,
    pub conditions: Vec<AttributeCondition>,
}

#[derive(Debug, Clone, Default)]
pub struct PolicyDocument {
    pub rules: Vec<PolicyRule>,
}

impl PolicyDocument {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
    }

    // Evaluates request. Explicit Deny ALWAYS overrides Allow!
    pub fn evaluate(
        &self,
        role_ids: &[u32],
        resource_path: &str,
        requested_perm: u32,
        context: &HashMap<String, String>,
    ) -> Effect {
        let mut has_allow = false;

        for rule in &self.rules {
            if role_ids.contains(&rule.role_id) 
                && rule.resource.matches(resource_path)
                && (rule.permissions & requested_perm) == requested_perm 
            {
                // Check optional ABAC conditions
                let conditions_pass = rule.conditions.iter().all(|c| c.evaluate(context));
                if conditions_pass {
                    if rule.effect == Effect::Deny {
                        return Effect::Deny; // Explicit deny immediately overrides
                    }
                    has_allow = true;
                }
            }
        }

        if has_allow {
            Effect::Allow
        } else {
            Effect::Deny
        }
    }
}

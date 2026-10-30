use wasm_bindgen::prelude::*;
use crate::graph::RoleGraph;
use crate::policy::{Effect, PolicyDocument, PolicyRule};
use crate::resource::ResourcePattern;
use std::collections::{HashMap, HashSet};

#[wasm_bindgen]
pub struct WasmEdgeRbac { graph: RoleGraph, policy: PolicyDocument }

#[wasm_bindgen]
impl WasmEdgeRbac {
    /// New engines deny all until trusted configuration adds explicit rules.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self { Self { graph: RoleGraph::new(), policy: PolicyDocument::new() } }

    pub fn add_inheritance(&mut self, child: u32, parent: u32) -> Result<(), JsValue> {
        if child == 0 || parent == 0 { return Err(JsValue::from_str("Invalid role")); }
        self.graph.add_edge_with_depth_limit(child, parent, RoleGraph::DEFAULT_MAX_DEPTH).map_err(JsValue::from_str)
    }

    pub fn add_rule(&mut self, id: &str, role: u32, resource: &str, permissions: u32, allow: bool) -> Result<(), JsValue> {
        let segments: Vec<&str> = resource.split(':').collect();
        if id.is_empty() || role == 0 || permissions == 0 || permissions & !1023 != 0 || resource.trim() != resource || segments.iter().any(|s| s.is_empty() || s.trim() != *s) || segments.iter().take(segments.len().saturating_sub(1)).any(|s| *s == "**") {
            return Err(JsValue::from_str("Invalid policy rule"));
        }
        self.policy.add_rule(PolicyRule { id: id.to_string(), effect: if allow { Effect::Allow } else { Effect::Deny }, role_id: role, resource: ResourcePattern::new(resource), permissions, conditions: Vec::new() });
        Ok(())
    }

    /// Evaluate all effective roles together so an explicit deny takes precedence.
    pub fn can_access_roles(&self, role_ids: &[u32], resource: &str, required_perm: u32) -> bool {
        if role_ids.is_empty() || resource.is_empty() || required_perm == 0 || required_perm & !1023 != 0 { return false; }
        let roles: HashSet<u32> = role_ids.iter().flat_map(|role| self.graph.get_effective_roles(*role)).collect();
        self.policy.evaluate(&roles.into_iter().collect::<Vec<_>>(), resource, required_perm, &HashMap::new()) == Effect::Allow
    }
}

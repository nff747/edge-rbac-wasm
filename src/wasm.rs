use wasm_bindgen::prelude::*;
use crate::graph::RoleGraph;
use crate::policy::{Effect, PolicyDocument, PolicyRule};
use crate::resource::ResourcePattern;
use crate::bitflags::*;
use std::collections::HashMap;

#[wasm_bindgen]
pub struct WasmEdgeRbac {
    graph: RoleGraph,
    policy: PolicyDocument,
}

#[wasm_bindgen]
impl WasmEdgeRbac {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let mut graph = RoleGraph::new();
        let _ = graph.add_edge(2, 1); // Editor -> Viewer
        let _ = graph.add_edge(3, 2); // Admin -> Editor

        let mut policy = PolicyDocument::new();
        policy.add_rule(PolicyRule {
            id: "default_read".to_string(),
            effect: Effect::Allow,
            role_id: 1,
            resource: ResourcePattern::new("**"),
            permissions: PERM_READ,
            conditions: Vec::new(),
        });
        policy.add_rule(PolicyRule {
            id: "default_write".to_string(),
            effect: Effect::Allow,
            role_id: 2,
            resource: ResourcePattern::new("**"),
            permissions: PERM_WRITE,
            conditions: Vec::new(),
        });
        policy.add_rule(PolicyRule {
            id: "default_admin".to_string(),
            effect: Effect::Allow,
            role_id: 3,
            resource: ResourcePattern::new("**"),
            permissions: PERM_ADMIN | PERM_DELETE,
            conditions: Vec::new(),
        });

        Self { graph, policy }
    }

    #[wasm_bindgen]
    pub fn can_access(&self, role_id: u32, resource: &str, required_perm: u32) -> bool {
        let roles: Vec<u32> = self.graph.get_effective_roles(role_id).into_iter().collect();
        let ctx = HashMap::new();
        self.policy.evaluate(&roles, resource, required_perm, &ctx) == Effect::Allow
    }
}

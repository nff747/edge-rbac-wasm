pub mod wasm;
pub mod validator;
pub mod compiler;
pub mod tenant;
pub mod audit;
pub mod cache;
pub mod policy;
pub mod graph;
pub mod abac;
pub mod resource;
pub mod bitflags;
use std::collections::{HashMap, HashSet};
use wasm_bindgen::prelude::*;

// Standard Permission Bitflags
pub const PERM_READ: u32 = 1 << 0;       // 0x01
pub const PERM_WRITE: u32 = 1 << 1;      // 0x02
pub const PERM_DELETE: u32 = 1 << 2;     // 0x04
pub const PERM_EXECUTE: u32 = 1 << 3;    // 0x08
pub const PERM_ADMIN: u32 = 1 << 4;      // 0x10

#[wasm_bindgen]
pub struct RbacEngine {
    // role_id -> direct permission bitmask
    role_permissions: HashMap<u32, u32>,
    // role_id -> set of parent role_ids inherited
    role_inheritance: HashMap<u32, HashSet<u32>>,
}

#[wasm_bindgen]
impl RbacEngine {
    #[wasm_bindgen(constructor)]
    pub fn new() -> RbacEngine {
        let mut engine = RbacEngine {
            role_permissions: HashMap::new(),
            role_inheritance: HashMap::new(),
        };

        // Built-in defaults:
        // Role 1 (Viewer): READ
        engine.assign_permission(1, PERM_READ);
        // Role 2 (Editor): READ | WRITE
        engine.assign_permission(2, PERM_READ | PERM_WRITE);
        // Role 3 (Admin): READ | WRITE | DELETE | EXECUTE | ADMIN
        engine.assign_permission(3, PERM_READ | PERM_WRITE | PERM_DELETE | PERM_EXECUTE | PERM_ADMIN);

        // Editor inherits from Viewer
        engine.inherit_role(2, 1);
        // Admin inherits from Editor
        engine.inherit_role(3, 2);

        engine
    }

    #[wasm_bindgen]
    pub fn assign_permission(&mut self, role_id: u32, permissions: u32) {
        let entry = self.role_permissions.entry(role_id).or_insert(0);
        *entry |= permissions;
    }

    #[wasm_bindgen]
    pub fn inherit_role(&mut self, child_role: u32, parent_role: u32) {
        self.role_inheritance.entry(child_role).or_default().insert(parent_role);
    }

    // Resolves effective permissions for a role including entire inheritance graph
    #[wasm_bindgen]
    pub fn get_effective_permissions(&self, role_id: u32) -> u32 {
        let mut effective = *self.role_permissions.get(&role_id).unwrap_or(&0);
        let mut visited = HashSet::new();
        let mut queue = vec![role_id];

        while let Some(current) = queue.pop() {
            if visited.insert(current) {
                if let Some(parents) = self.role_inheritance.get(&current) {
                    for &parent in parents {
                        effective |= self.role_permissions.get(&parent).unwrap_or(&0);
                        if !visited.contains(&parent) {
                            queue.push(parent);
                        }
                    }
                }
            }
        }

        effective
    }

    #[wasm_bindgen]
    pub fn can(&self, role_id: u32, required_permission: u32) -> bool {
        let effective = self.get_effective_permissions(role_id);
        (effective & required_permission) == required_permission
    }

    #[wasm_bindgen]
    pub fn can_tenant(
        &self,
        user_tenant_id: u32,
        user_role_id: u32,
        target_tenant_id: u32,
        required_permission: u32,
    ) -> bool {
        // Enforce strict tenant boundary isolation unless caller has cross-tenant admin flag
        if user_tenant_id != target_tenant_id {
            let effective = self.get_effective_permissions(user_role_id);
            if (effective & PERM_ADMIN) == 0 {
                return false;
            }
        }
        self.can(user_role_id, required_permission)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_built_in_role_permissions() {
        let engine = RbacEngine::new();
        // Viewer can read, cannot write
        assert!(engine.can(1, PERM_READ));
        assert!(!engine.can(1, PERM_WRITE));

        // Editor can read and write, cannot delete
        assert!(engine.can(2, PERM_READ));
        assert!(engine.can(2, PERM_WRITE));
        assert!(!engine.can(2, PERM_DELETE));

        // Admin can read, write, delete, execute, admin
        assert!(engine.can(3, PERM_READ | PERM_WRITE | PERM_DELETE));
        assert!(engine.can(3, PERM_ADMIN));
    }

    #[test]
    fn test_dynamic_custom_role_inheritance() {
        let mut engine = RbacEngine::new();
        // Create custom auditor role: 10
        engine.assign_permission(10, PERM_READ | PERM_EXECUTE);
        // Custom security lead: 20 inherits auditor
        engine.assign_permission(20, PERM_DELETE);
        engine.inherit_role(20, 10);

        assert!(engine.can(20, PERM_READ | PERM_DELETE));
        assert!(engine.can(20, PERM_EXECUTE));
        assert!(!engine.can(20, PERM_WRITE));
    }

    #[test]
    fn test_tenant_boundary_isolation() {
        let engine = RbacEngine::new();
        let tenant_alpha = 101;
        let tenant_beta = 102;

        // Editor in tenant Alpha cannot write to tenant Beta
        assert!(!engine.can_tenant(tenant_alpha, 2, tenant_beta, PERM_WRITE));
        // Editor in tenant Alpha can write within tenant Alpha
        assert!(engine.can_tenant(tenant_alpha, 2, tenant_alpha, PERM_WRITE));

        // Global Admin (Role 3) can access across tenant boundary
        assert!(engine.can_tenant(tenant_alpha, 3, tenant_beta, PERM_READ | PERM_WRITE));
    }
}

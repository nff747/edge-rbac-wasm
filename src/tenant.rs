use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct TenantHierarchy {
    // subtenant_id -> parent_tenant_id (e.g. team -> organization)
    parents: HashMap<u32, u32>,
}

impl TenantHierarchy {
    pub fn new() -> Self {
        Self { parents: HashMap::new() }
    }

    pub fn set_parent(&mut self, subtenant: u32, parent: u32) {
        self.parents.insert(subtenant, parent);
    }

    pub fn is_accessible(&self, user_tenant: u32, target_tenant: u32) -> bool {
        if user_tenant == target_tenant {
            return true;
        }

        // Parent organization can access its child subtenants
        let mut curr = target_tenant;
        while let Some(&p) = self.parents.get(&curr) {
            if p == user_tenant {
                return true;
            }
            curr = p;
        }

        false
    }
}

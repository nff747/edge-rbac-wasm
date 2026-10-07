use crate::graph::RoleGraph;
use crate::policy::{Effect, PolicyDocument};
use crate::tenant::TenantHierarchy;
use crate::cache::{DecisionCache, DecisionCacheKey};
use crate::audit::AuditLogEntry;
use std::collections::HashMap;

pub struct UnifiedEngine {
    pub graph: RoleGraph,
    pub policy: PolicyDocument,
    pub tenant: TenantHierarchy,
    pub cache: DecisionCache,
}

impl UnifiedEngine {
    pub fn new(cache_size: usize) -> Self {
        Self {
            graph: RoleGraph::new(),
            policy: PolicyDocument::new(),
            tenant: TenantHierarchy::new(),
            cache: DecisionCache::new(cache_size),
        }
    }

    pub fn authorize(
        &mut self,
        user_tenant: u32,
        user_role: u32,
        target_tenant: u32,
        resource: &str,
        permission: u32,
        request_id: &str,
        context: &HashMap<String, String>,
    ) -> (bool, AuditLogEntry) {
        // 1. Check multi-tenant boundary
        if !self.tenant.is_accessible(user_tenant, target_tenant) {
            let audit = AuditLogEntry::new(
                0,
                request_id,
                user_tenant,
                user_role,
                resource,
                permission,
                false,
                "Tenant boundary isolation violation",
            );
            return (false, audit);
        }

        // 2. Check Decision Cache
        let cache_key = DecisionCacheKey {
            role_id: user_role,
            resource: resource.to_string(),
            permission,
        };

        if context.is_empty() {
            if let Some(cached) = self.cache.get(&cache_key) {
                let audit = AuditLogEntry::new(
                    0,
                    request_id,
                    user_tenant,
                    user_role,
                    resource,
                    permission,
                    cached,
                    "Cache hit",
                );
                return (cached, audit);
            }
        }

        // 3. Resolve role inheritance
        let roles: Vec<u32> = self.graph.get_effective_roles(user_role).into_iter().collect();

        // 4. Evaluate Policy
        let effect = self.policy.evaluate(&roles, resource, permission, context);
        let granted = effect == Effect::Allow;

        if context.is_empty() {
            self.cache.put(cache_key, granted);
        }

        let audit = AuditLogEntry::new(
            0,
            request_id,
            user_tenant,
            user_role,
            resource,
            permission,
            granted,
            if granted { "Policy Allow" } else { "Policy Deny" },
        );

        (granted, audit)
    }
}

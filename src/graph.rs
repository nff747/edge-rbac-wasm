use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Default)]
pub struct RoleGraph {
    // child -> set of parents
    parents: HashMap<u32, HashSet<u32>>,
}

impl RoleGraph {
    pub fn new() -> Self {
        Self {
            parents: HashMap::new(),
        }
    }

    // Add inheritance link (child inherits parent). Rejects cyclic relationships!
    pub fn add_edge(&mut self, child: u32, parent: u32) -> Result<(), &'static str> {
        if child == parent {
            return Err("Self-inheritance cycle detected");
        }

        // Check if parent already inherits child (would form a cycle)
        let ancestors = self.get_all_ancestors(parent);
        if ancestors.contains(&child) {
            return Err("Cyclic inheritance detected in role graph");
        }

        self.parents.entry(child).or_default().insert(parent);
        Ok(())
    }

    pub fn get_all_ancestors(&self, role_id: u32) -> HashSet<u32> {
        let mut result = HashSet::new();
        let mut queue = vec![role_id];

        while let Some(current) = queue.pop() {
            if let Some(direct_parents) = self.parents.get(&current) {
                for &p in direct_parents {
                    if result.insert(p) {
                        queue.push(p);
                    }
                }
            }
        }

        result
    }

    pub fn get_effective_roles(&self, role_id: u32) -> HashSet<u32> {
        let mut roles = self.get_all_ancestors(role_id);
        roles.insert(role_id);
        roles
    }
}

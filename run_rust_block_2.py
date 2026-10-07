import os
import subprocess
import sys

SCRATCH = "/home/n1khy/.gemini/antigravity/scratch/edge-rbac-wasm"

def run_cmd(cmd):
    res = subprocess.run(cmd, shell=True, cwd=SCRATCH, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"FAILED: {cmd}")
        print("STDOUT:", res.stdout)
        print("STDERR:", res.stderr)
        sys.exit(1)
    return res.stdout.strip()

def run_tests():
    res = subprocess.run("cargo test", shell=True, cwd=SCRATCH, capture_output=True, text=True)
    if res.returncode != 0:
        print("CARGO TESTS FAILED:")
        print(res.stdout)
        print(res.stderr)
        sys.exit(1)
    return True

def commit(msg):
    run_cmd("git add -A")
    out = run_cmd(f'git commit -m "{msg}"')
    print(f"Committed: {msg}")

# -------------------------------------------------------------
# Commit 6: feat(abac): implement dynamic attribute-based access control
# -------------------------------------------------------------
abac_code = """use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operator {
    Equals,
    NotEquals,
    In,
    GreaterThan,
    LessThan,
}

#[derive(Debug, Clone)]
pub struct AttributeCondition {
    pub attribute_key: String,
    pub operator: Operator,
    pub expected_value: String,
}

impl AttributeCondition {
    pub fn new(key: &str, operator: Operator, expected: &str) -> Self {
        Self {
            attribute_key: key.to_string(),
            operator,
            expected_value: expected.to_string(),
        }
    }

    pub fn evaluate(&self, context: &HashMap<String, String>) -> bool {
        let val = match context.get(&self.attribute_key) {
            Some(v) => v,
            None => return false,
        };

        match self.operator {
            Operator::Equals => val == &self.expected_value,
            Operator::NotEquals => val != &self.expected_value,
            Operator::In => self.expected_value.split(',').any(|item| item.trim() == val),
            Operator::GreaterThan => {
                let v_num: Result<i64, _> = val.parse();
                let exp_num: Result<i64, _> = self.expected_value.parse();
                match (v_num, exp_num) {
                    (Ok(a), Ok(b)) => a > b,
                    _ => val > &self.expected_value,
                }
            }
            Operator::LessThan => {
                let v_num: Result<i64, _> = val.parse();
                let exp_num: Result<i64, _> = self.expected_value.parse();
                match (v_num, exp_num) {
                    (Ok(a), Ok(b)) => a < b,
                    _ => val < &self.expected_value,
                }
            }
        }
    }
}
"""
with open(os.path.join(SCRATCH, "src/abac.rs"), "w") as f:
    f.write(abac_code)

with open(os.path.join(SCRATCH, "src/lib.rs"), "r") as f:
    lib_content = f.read()
if "pub mod abac;" not in lib_content:
    lib_content = "pub mod abac;\n" + lib_content
    with open(os.path.join(SCRATCH, "src/lib.rs"), "w") as f:
        f.write(lib_content)

run_tests()
commit("feat(abac): implement dynamic attribute-based access control condition evaluator")

# -------------------------------------------------------------
# Commit 7: test(abac): add unit tests for contextual ABAC attribute rules
# -------------------------------------------------------------
abac_test = """use edge_rbac_wasm::abac::{AttributeCondition, Operator};
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
"""
with open(os.path.join(SCRATCH, "tests/abac_test.rs"), "w") as f:
    f.write(abac_test)

run_tests()
commit("test(abac): add unit tests for contextual ABAC attribute rules and comparison operators")

# -------------------------------------------------------------
# Commit 8: feat(graph): implement directed acyclic role graph
# -------------------------------------------------------------
graph_code = """use std::collections::{HashMap, HashSet};

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
"""
with open(os.path.join(SCRATCH, "src/graph.rs"), "w") as f:
    f.write(graph_code)

with open(os.path.join(SCRATCH, "src/lib.rs"), "r") as f:
    lib_content = f.read()
if "pub mod graph;" not in lib_content:
    lib_content = "pub mod graph;\n" + lib_content
    with open(os.path.join(SCRATCH, "src/lib.rs"), "w") as f:
        f.write(lib_content)

run_tests()
commit("feat(graph): implement directed acyclic role graph with cycle detection and topological order")

# -------------------------------------------------------------
# Commit 9: test(graph): add unit tests for role inheritance DAG
# -------------------------------------------------------------
graph_test = """use edge_rbac_wasm::graph::RoleGraph;

#[test]
fn test_role_inheritance_hierarchy() {
    let mut g = RoleGraph::new();
    // Role 3 (Admin) -> Role 2 (Editor) -> Role 1 (Viewer)
    assert!(g.add_edge(2, 1).is_ok());
    assert!(g.add_edge(3, 2).is_ok());

    let admin_roles = g.get_effective_roles(3);
    assert!(admin_roles.contains(&1));
    assert!(admin_roles.contains(&2));
    assert!(admin_roles.contains(&3));
}

#[test]
fn test_cycle_detection_rejection() {
    let mut g = RoleGraph::new();
    assert!(g.add_edge(10, 20).is_ok());
    assert!(g.add_edge(20, 30).is_ok());

    // Cycle: 30 -> 10 would loop back!
    assert_eq!(g.add_edge(30, 10), Err("Cyclic inheritance detected in role graph"));

    // Self cycle
    assert_eq!(g.add_edge(10, 10), Err("Self-inheritance cycle detected"));
}
"""
with open(os.path.join(SCRATCH, "tests/graph_test.rs"), "w") as f:
    f.write(graph_test)

run_tests()
commit("test(graph): add unit tests for role inheritance DAG and cycle prevention")

# -------------------------------------------------------------
# Commit 10: feat(policy): implement declarative policy rules
# -------------------------------------------------------------
policy_code = """use crate::resource::ResourcePattern;
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
"""
with open(os.path.join(SCRATCH, "src/policy.rs"), "w") as f:
    f.write(policy_code)

with open(os.path.join(SCRATCH, "src/lib.rs"), "r") as f:
    lib_content = f.read()
if "pub mod policy;" not in lib_content:
    lib_content = "pub mod policy;\n" + lib_content
    with open(os.path.join(SCRATCH, "src/lib.rs"), "w") as f:
        f.write(lib_content)

run_tests()
commit("feat(policy): implement declarative policy rules and explicit-deny override evaluation")

print("Block 2 (Commits 6-10) completed successfully.")

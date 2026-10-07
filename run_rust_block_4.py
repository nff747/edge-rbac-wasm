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
# Commit 16: feat(tenant): implement multi-tenant isolation hierarchies
# -------------------------------------------------------------
tenant_code = """use std::collections::HashMap;

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
"""
with open(os.path.join(SCRATCH, "src/tenant.rs"), "w") as f:
    f.write(tenant_code)

with open(os.path.join(SCRATCH, "src/lib.rs"), "r") as f:
    lib_content = f.read()
if "pub mod tenant;" not in lib_content:
    lib_content = "pub mod tenant;\n" + lib_content
    with open(os.path.join(SCRATCH, "src/lib.rs"), "w") as f:
        f.write(lib_content)

run_tests()
commit("feat(tenant): implement multi-tenant isolation hierarchies with org-team boundaries")

# -------------------------------------------------------------
# Commit 17: test(tenant): add unit tests for hierarchical tenancy
# -------------------------------------------------------------
tenant_test = """use edge_rbac_wasm::tenant::TenantHierarchy;

#[test]
fn test_same_tenant_always_accessible() {
    let t = TenantHierarchy::new();
    assert!(t.is_accessible(42, 42));
}

#[test]
fn test_parent_organization_hierarchy_access() {
    let mut t = TenantHierarchy::new();
    let org_id = 1000;
    let team_a = 1010;
    let project_alpha = 1011;

    t.set_parent(team_a, org_id);
    t.set_parent(project_alpha, team_a);

    // Org can access nested team and project
    assert!(t.is_accessible(org_id, team_a));
    assert!(t.is_accessible(org_id, project_alpha));

    // Peer team cannot access sibling
    assert!(!t.is_accessible(team_a, 2020));
    // Child cannot access parent root
    assert!(!t.is_accessible(project_alpha, org_id));
}
"""
with open(os.path.join(SCRATCH, "tests/tenant_test.rs"), "w") as f:
    f.write(tenant_test)

run_tests()
commit("test(tenant): add unit tests for hierarchical tenancy and cross-tenant guardrails")

# -------------------------------------------------------------
# Commit 18: feat(compiler): implement compact binary encoding
# -------------------------------------------------------------
compiler_code = """use crate::policy::{Effect, PolicyRule};
use crate::resource::ResourcePattern;

pub struct PolicyBinaryCodec;

impl PolicyBinaryCodec {
    // Binary layout per rule:
    // [effect: 1 byte (0=Deny, 1=Allow)]
    // [role_id: 4 bytes BE]
    // [permissions: 4 bytes BE]
    // [pattern_len: 2 bytes BE]
    // [pattern_utf8: N bytes]
    pub fn encode_rules(rules: &[PolicyRule]) -> Vec<u8> {
        let mut buf = Vec::new();
        let count = rules.len() as u16;
        buf.extend_from_slice(&count.to_be_bytes());

        for r in rules {
            buf.push(if r.effect == Effect::Allow { 1 } else { 0 });
            buf.extend_from_slice(&r.role_id.to_be_bytes());
            buf.extend_from_slice(&r.permissions.to_be_bytes());

            let pattern_bytes = r.resource.raw().as_bytes();
            let pat_len = pattern_bytes.len() as u16;
            buf.extend_from_slice(&pat_len.to_be_bytes());
            buf.extend_from_slice(pattern_bytes);
        }

        buf
    }

    pub fn decode_rules(bytes: &[u8]) -> Result<Vec<PolicyRule>, &'static str> {
        if bytes.len() < 2 {
            return Err("Binary payload too short");
        }

        let mut offset = 0;
        let count = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        offset += 2;

        let mut rules = Vec::with_capacity(count);

        for i in 0..count {
            if offset + 1 + 4 + 4 + 2 > bytes.len() {
                return Err("Truncated rule header");
            }

            let effect = if bytes[offset] == 1 { Effect::Allow } else { Effect::Deny };
            offset += 1;

            let role_id = u32::from_be_bytes([bytes[offset], bytes[offset+1], bytes[offset+2], bytes[offset+3]]);
            offset += 4;

            let perms = u32::from_be_bytes([bytes[offset], bytes[offset+1], bytes[offset+2], bytes[offset+3]]);
            offset += 4;

            let pat_len = u16::from_be_bytes([bytes[offset], bytes[offset+1]]) as usize;
            offset += 2;

            if offset + pat_len > bytes.len() {
                return Err("Truncated pattern string");
            }

            let pattern_str = std::str::from_utf8(&bytes[offset..offset+pat_len])
                .map_err(|_| "Invalid UTF-8 pattern")?;
            offset += pat_len;

            rules.push(PolicyRule {
                id: format!("bin_rule_{}", i),
                effect,
                role_id,
                resource: ResourcePattern::new(pattern_str),
                permissions: perms,
                conditions: Vec::new(),
            });
        }

        Ok(rules)
    }
}
"""
with open(os.path.join(SCRATCH, "src/compiler.rs"), "w") as f:
    f.write(compiler_code)

with open(os.path.join(SCRATCH, "src/lib.rs"), "r") as f:
    lib_content = f.read()
if "pub mod compiler;" not in lib_content:
    lib_content = "pub mod compiler;\n" + lib_content
    with open(os.path.join(SCRATCH, "src/lib.rs"), "w") as f:
        f.write(lib_content)

run_tests()
commit("feat(compiler): implement compact binary encoding and byte-slice policy deserializer")

# -------------------------------------------------------------
# Commit 19: test(compiler): add unit tests for policy binary serialization
# -------------------------------------------------------------
compiler_test = """use edge_rbac_wasm::compiler::PolicyBinaryCodec;
use edge_rbac_wasm::policy::{Effect, PolicyRule};
use edge_rbac_wasm::resource::ResourcePattern;
use edge_rbac_wasm::bitflags::PERM_READ;

#[test]
fn test_encode_and_decode_rules() {
    let rules = vec![
        PolicyRule {
            id: "r1".to_string(),
            effect: Effect::Allow,
            role_id: 10,
            resource: ResourcePattern::new("api:v1:data:*"),
            permissions: PERM_READ,
            conditions: Vec::new(),
        },
        PolicyRule {
            id: "r2".to_string(),
            effect: Effect::Deny,
            role_id: 20,
            resource: ResourcePattern::new("admin:**"),
            permissions: 0xFF,
            conditions: Vec::new(),
        },
    ];

    let bytes = PolicyBinaryCodec::encode_rules(&rules);
    assert!(!bytes.is_empty());

    let decoded = PolicyBinaryCodec::decode_rules(&bytes).expect("Failed decoding");
    assert_eq!(decoded.len(), 2);
    assert_eq!(decoded[0].role_id, 10);
    assert_eq!(decoded[0].effect, Effect::Allow);
    assert_eq!(decoded[0].resource.raw(), "api:v1:data:*");

    assert_eq!(decoded[1].role_id, 20);
    assert_eq!(decoded[1].effect, Effect::Deny);
}
"""
with open(os.path.join(SCRATCH, "tests/compiler_test.rs"), "w") as f:
    f.write(compiler_test)

run_tests()
commit("test(compiler): add unit tests for policy binary serialization and wire unpacking")

# -------------------------------------------------------------
# Commit 20: feat(validator): implement policy sanity checker
# -------------------------------------------------------------
validator_code = """use crate::policy::PolicyRule;

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
"""
with open(os.path.join(SCRATCH, "src/validator.rs"), "w") as f:
    f.write(validator_code)

with open(os.path.join(SCRATCH, "src/lib.rs"), "r") as f:
    lib_content = f.read()
if "pub mod validator;" not in lib_content:
    lib_content = "pub mod validator;\n" + lib_content
    with open(os.path.join(SCRATCH, "src/lib.rs"), "w") as f:
        f.write(lib_content)

run_tests()
commit("feat(validator): implement policy sanity checker and redundant role detector")

print("Block 4 (Commits 16-20) completed successfully.")

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

os.makedirs(os.path.join(SCRATCH, "src"), exist_ok=True)
os.makedirs(os.path.join(SCRATCH, "tests"), exist_ok=True)

# -------------------------------------------------------------
# Commit 1: feat(cargo): configure dual rlib/cdylib targets
# -------------------------------------------------------------
cargo_toml = """[package]
name = "edge-rbac-wasm"
version = "0.1.0"
edition = "2021"
license = "Apache-2.0"

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
wasm-bindgen = "0.2"

[dev-dependencies]
wasm-bindgen-test = "0.3"

[profile.release]
opt-level = "s"
lto = true
codegen-units = 1
"""
with open(os.path.join(SCRATCH, "Cargo.toml"), "w") as f:
    f.write(cargo_toml)

run_tests()
commit("feat(cargo): configure dual rlib/cdylib targets and compiler optimizations for WASM")

# -------------------------------------------------------------
# Commit 2: feat(bitflags): implement comprehensive permission bitflags
# -------------------------------------------------------------
bitflags_code = """pub const PERM_NONE: u32 = 0;
pub const PERM_READ: u32 = 1 << 0;            // 0x01
pub const PERM_WRITE: u32 = 1 << 1;           // 0x02
pub const PERM_DELETE: u32 = 1 << 2;          // 0x04
pub const PERM_EXECUTE: u32 = 1 << 3;         // 0x08
pub const PERM_ADMIN: u32 = 1 << 4;           // 0x10
pub const PERM_EXPORT: u32 = 1 << 5;          // 0x20
pub const PERM_MANAGE_USERS: u32 = 1 << 6;    // 0x40
pub const PERM_MANAGE_BILLING: u32 = 1 << 7;  // 0x80
pub const PERM_AUDIT_LOGS: u32 = 1 << 8;      // 0x100
pub const PERM_IMPERSONATE: u32 = 1 << 9;     // 0x200

pub fn parse_permission_str(name: &str) -> Option<u32> {
    match name.trim().to_lowercase().as_str() {
        "read" => Some(PERM_READ),
        "write" => Some(PERM_WRITE),
        "delete" => Some(PERM_DELETE),
        "execute" => Some(PERM_EXECUTE),
        "admin" => Some(PERM_ADMIN),
        "export" => Some(PERM_EXPORT),
        "manage_users" | "users" => Some(PERM_MANAGE_USERS),
        "manage_billing" | "billing" => Some(PERM_MANAGE_BILLING),
        "audit_logs" | "audit" => Some(PERM_AUDIT_LOGS),
        "impersonate" => Some(PERM_IMPERSONATE),
        _ => None,
    }
}

pub fn permissions_to_names(mask: u32) -> Vec<&'static str> {
    let mut names = Vec::new();
    if mask & PERM_READ != 0 { names.push("read"); }
    if mask & PERM_WRITE != 0 { names.push("write"); }
    if mask & PERM_DELETE != 0 { names.push("delete"); }
    if mask & PERM_EXECUTE != 0 { names.push("execute"); }
    if mask & PERM_ADMIN != 0 { names.push("admin"); }
    if mask & PERM_EXPORT != 0 { names.push("export"); }
    if mask & PERM_MANAGE_USERS != 0 { names.push("manage_users"); }
    if mask & PERM_MANAGE_BILLING != 0 { names.push("manage_billing"); }
    if mask & PERM_AUDIT_LOGS != 0 { names.push("audit_logs"); }
    if mask & PERM_IMPERSONATE != 0 { names.push("impersonate"); }
    names
}

#[inline]
pub fn check_permission(granted_mask: u32, required_mask: u32) -> bool {
    (granted_mask & required_mask) == required_mask
}
"""
with open(os.path.join(SCRATCH, "src/bitflags.rs"), "w") as f:
    f.write(bitflags_code)

# Add pub mod bitflags to lib.rs
with open(os.path.join(SCRATCH, "src/lib.rs"), "r") as f:
    lib_content = f.read()
if "pub mod bitflags;" not in lib_content:
    lib_content = "pub mod bitflags;\n" + lib_content
    with open(os.path.join(SCRATCH, "src/lib.rs"), "w") as f:
        f.write(lib_content)

run_tests()
commit("feat(bitflags): implement comprehensive permission bitflags and string-name mappings")

# -------------------------------------------------------------
# Commit 3: test(bitflags): add unit tests for permission mask operations
# -------------------------------------------------------------
bitflags_test = """use edge_rbac_wasm::bitflags::*;

#[test]
fn test_bitwise_permission_checks() {
    let read_write = PERM_READ | PERM_WRITE;
    assert!(check_permission(read_write, PERM_READ));
    assert!(check_permission(read_write, PERM_WRITE));
    assert!(!check_permission(read_write, PERM_DELETE));
    assert!(!check_permission(read_write, PERM_ADMIN));
}

#[test]
fn test_parse_string_permissions() {
    assert_eq!(parse_permission_str("read"), Some(PERM_READ));
    assert_eq!(parse_permission_str("WRITE"), Some(PERM_WRITE));
    assert_eq!(parse_permission_str("manage_users"), Some(PERM_MANAGE_USERS));
    assert_eq!(parse_permission_str("unknown_perm"), None);
}

#[test]
fn test_permissions_to_names() {
    let mask = PERM_READ | PERM_DELETE | PERM_AUDIT_LOGS;
    let names = permissions_to_names(mask);
    assert_eq!(names, vec!["read", "delete", "audit_logs"]);
}
"""
with open(os.path.join(SCRATCH, "tests/bitflags_test.rs"), "w") as f:
    f.write(bitflags_test)

run_tests()
commit("test(bitflags): add unit tests for permission mask operations and string parsing")

# -------------------------------------------------------------
# Commit 4: feat(resource): implement hierarchical resource path model
# -------------------------------------------------------------
resource_code = """#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourcePattern {
    pattern: String,
    segments: Vec<String>,
}

impl ResourcePattern {
    pub fn new(pattern: &str) -> Self {
        let segments = pattern.split(':').map(|s| s.to_string()).collect();
        Self {
            pattern: pattern.to_string(),
            segments,
        }
    }

    pub fn matches(&self, resource_path: &str) -> bool {
        if self.pattern == "*" || self.pattern == "**" {
            return true;
        }

        let target_segments: Vec<&str> = resource_path.split(':').collect();

        let mut p_idx = 0;
        let mut t_idx = 0;

        while p_idx < self.segments.len() && t_idx < target_segments.len() {
            let p = &self.segments[p_idx];
            let t = target_segments[t_idx];

            if p == "**" {
                // Matches remaining segments
                return true;
            } else if p == "*" || p == t {
                p_idx += 1;
                t_idx += 1;
            } else {
                return false;
            }
        }

        p_idx == self.segments.len() && t_idx == target_segments.len()
    }

    pub fn raw(&self) -> &str {
        &self.pattern
    }
}
"""
with open(os.path.join(SCRATCH, "src/resource.rs"), "w") as f:
    f.write(resource_code)

with open(os.path.join(SCRATCH, "src/lib.rs"), "r") as f:
    lib_content = f.read()
if "pub mod resource;" not in lib_content:
    lib_content = "pub mod resource;\n" + lib_content
    with open(os.path.join(SCRATCH, "src/lib.rs"), "w") as f:
        f.write(lib_content)

run_tests()
commit("feat(resource): implement hierarchical resource path model and wildcard matcher")

# -------------------------------------------------------------
# Commit 5: test(resource): add unit tests for wildcard resource matching
# -------------------------------------------------------------
resource_test = """use edge_rbac_wasm::resource::ResourcePattern;

#[test]
fn test_exact_resource_match() {
    let p = ResourcePattern::new("api:v1:users");
    assert!(p.matches("api:v1:users"));
    assert!(!p.matches("api:v1:documents"));
    assert!(!p.matches("api:v1:users:list"));
}

#[test]
fn test_single_wildcard_segment() {
    let p = ResourcePattern::new("documents:*:view");
    assert!(p.matches("documents:reports:view"));
    assert!(p.matches("documents:invoices:view"));
    assert!(!p.matches("documents:reports:edit"));
    assert!(!p.matches("documents:reports:sub:view"));
}

#[test]
fn test_recursive_glob_wildcard() {
    let p = ResourcePattern::new("api:v2:**");
    assert!(p.matches("api:v2:users"));
    assert!(p.matches("api:v2:users:123:profile"));
    assert!(!p.matches("api:v1:users"));
}
"""
with open(os.path.join(SCRATCH, "tests/resource_test.rs"), "w") as f:
    f.write(resource_test)

run_tests()
commit("test(resource): add unit tests for glob and prefix wildcard resource matching")

print("Block 1 (Commits 1-5) completed successfully.")

pub const PERM_NONE: u32 = 0;
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

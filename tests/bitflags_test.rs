use edge_rbac_wasm::bitflags::*;

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

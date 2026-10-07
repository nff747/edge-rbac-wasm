use edge_rbac_wasm::audit::AuditLogEntry;

#[test]
fn test_audit_log_entry_creation() {
    let entry = AuditLogEntry::new(
        1700000000000,
        "req_abc123",
        1001,
        2,
        "api:v1:billing",
        4,
        false,
        "Missing PERM_DELETE permission",
    );

    assert_eq!(entry.request_id, "req_abc123");
    assert_eq!(entry.granted, false);

    let tsv = entry.to_tsv_line();
    assert!(tsv.contains("req_abc123"));
    assert!(tsv.contains("DENY"));
    assert!(tsv.contains("Missing PERM_DELETE permission"));
}

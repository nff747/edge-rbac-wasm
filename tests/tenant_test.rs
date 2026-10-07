use edge_rbac_wasm::tenant::TenantHierarchy;

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

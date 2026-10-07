use edge_rbac_wasm::graph::RoleGraph;

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

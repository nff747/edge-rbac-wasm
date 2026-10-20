use edge_rbac_wasm::resource::ResourcePattern;

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

#[test]
fn test_resource_normalization_and_whitespace_trimming() {
    let p = ResourcePattern::new(" :api:v1:users: ");
    assert_eq!(p.raw(), "api:v1:users");
    assert!(p.matches("  api:v1:users  "));
    assert!(p.matches(":api:v1:users:"));
}

#[test]
fn test_is_exact_and_is_wildcard_detection() {
    let exact = ResourcePattern::new("api:v1:orders:create");
    assert!(exact.is_exact());
    assert!(!exact.is_wildcard());

    let single_wildcard = ResourcePattern::new("api:v1:orders:*");
    assert!(!single_wildcard.is_exact());
    assert!(single_wildcard.is_wildcard());

    let glob_wildcard = ResourcePattern::new("api:**");
    assert!(!glob_wildcard.is_exact());
    assert!(glob_wildcard.is_wildcard());
}

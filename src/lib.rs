use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct RbacEngine {
    // Bitmask representation of rules
    rules: u64, 
}

#[wasm_bindgen]
impl RbacEngine {
    #[wasm_bindgen(constructor)]
    pub fn new() -> RbacEngine {
        RbacEngine { rules: 0xFF }
    }

    #[wasm_bindgen]
    pub fn can(&self, user_role_mask: u64, resource_mask: u64) -> bool {
        // Microsecond evaluation via bitwise AND
        (user_role_mask & resource_mask & self.rules) > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rbac_default_rules() {
        let engine = RbacEngine::new();
        assert!(engine.can(0x01, 0x01));
        assert!(!engine.can(0x1000, 0x1000));
    }

    #[test]
    fn test_rbac_bitwise_disjoint() {
        let engine = RbacEngine::new();
        // Disjoint user role and resource mask
        assert!(!engine.can(0x02, 0x04));
    }
}


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

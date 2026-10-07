use crate::policy::{Effect, PolicyRule};
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

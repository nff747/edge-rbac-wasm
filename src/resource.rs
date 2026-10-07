#[derive(Debug, Clone, PartialEq, Eq)]
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

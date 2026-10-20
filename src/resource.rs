#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourcePattern {
    pattern: String,
    segments: Vec<String>,
}

impl ResourcePattern {
    pub fn new(pattern: &str) -> Self {
        let normalized = Self::normalize_path(pattern);
        let segments = normalized.split(':').map(|s| s.to_string()).collect();
        Self {
            pattern: normalized,
            segments,
        }
    }

    pub fn normalize_path(path: &str) -> String {
        path.trim()
            .trim_matches(':')
            .split(':')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect::<Vec<&str>>()
            .join(":")
    }

    pub fn is_exact(&self) -> bool {
        !self.segments.iter().any(|s| s == "*" || s == "**")
    }

    pub fn is_wildcard(&self) -> bool {
        !self.is_exact()
    }

    pub fn matches(&self, resource_path: &str) -> bool {
        if self.pattern == "*" || self.pattern == "**" {
            return true;
        }

        let normalized_target = Self::normalize_path(resource_path);
        let target_segments: Vec<&str> = normalized_target.split(':').collect();

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

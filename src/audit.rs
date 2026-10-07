#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditLogEntry {
    pub timestamp_ms: u64,
    pub request_id: String,
    pub tenant_id: u32,
    pub role_id: u32,
    pub resource: String,
    pub permission: u32,
    pub granted: bool,
    pub reason: String,
}

impl AuditLogEntry {
    pub fn new(
        timestamp_ms: u64,
        request_id: &str,
        tenant_id: u32,
        role_id: u32,
        resource: &str,
        permission: u32,
        granted: bool,
        reason: &str,
    ) -> Self {
        Self {
            timestamp_ms,
            request_id: request_id.to_string(),
            tenant_id,
            role_id,
            resource: resource.to_string(),
            permission,
            granted,
            reason: reason.to_string(),
        }
    }

    pub fn to_tsv_line(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.timestamp_ms,
            self.request_id,
            self.tenant_id,
            self.role_id,
            self.resource,
            self.permission,
            if self.granted { "ALLOW" } else { "DENY" },
            self.reason
        )
    }
}

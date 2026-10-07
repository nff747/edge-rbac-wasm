export type PermissionFlag = 
  | 'read'
  | 'write'
  | 'delete'
  | 'execute'
  | 'admin'
  | 'export'
  | 'manage_users'
  | 'manage_billing'
  | 'audit_logs'
  | 'impersonate';

export interface RbacUser {
  id: string;
  tenantId: number;
  roles: number[];
  attributes?: Record<string, string>;
}

export interface RbacDecision {
  granted: boolean;
  reason: string;
  cached: boolean;
  evaluatedAt: number;
}

export interface AuditEntry {
  timestamp: number;
  requestId: string;
  tenantId: number;
  roleId: number;
  resource: string;
  permission: string;
  granted: boolean;
  reason: string;
}

export interface EdgeRbacConfig {
  cacheCapacity?: number;
  enableAuditLogging?: boolean;
  enforceTenantBoundary?: boolean;
}

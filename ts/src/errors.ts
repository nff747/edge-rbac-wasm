export class RbacError extends Error {
  public readonly code: string;
  public readonly status: number;

  constructor(message: string, code: string = 'RBAC_ERROR', status: number = 403) {
    super(message);
    this.name = 'RbacError';
    this.code = code;
    this.status = status;
  }

  public toJSON() {
    return {
      error: this.name,
      code: this.code,
      message: this.message
    };
  }
}

export class PermissionDeniedError extends RbacError {
  constructor(resource: string, permission: string) {
    super(`Access denied for ${permission} on ${resource}`, 'PERMISSION_DENIED', 403);
    this.name = 'PermissionDeniedError';
  }
}

export class TenantIsolationError extends RbacError {
  constructor(userTenant: number, targetTenant: number) {
    super(`Cross-tenant boundary access denied (source: ${userTenant}, target: ${targetTenant})`, 'TENANT_ISOLATION_VIOLATION', 403);
    this.name = 'TenantIsolationError';
  }
}

import { RbacUser, RbacDecision, PermissionFlag, EdgeRbacConfig } from './types';
import { WasmLoader } from './wasm_loader';

export const PERM_MAP: Record<PermissionFlag, number> = {
  read: 1 << 0,
  write: 1 << 1,
  delete: 1 << 2,
  execute: 1 << 3,
  admin: 1 << 4,
  export: 1 << 5,
  manage_users: 1 << 6,
  manage_billing: 1 << 7,
  audit_logs: 1 << 8,
  impersonate: 1 << 9
};

export class EdgeRbacClient {
  private config: EdgeRbacConfig;

  constructor(config: EdgeRbacConfig = {}) {
    this.config = {
      enforceTenantBoundary: true,
      ...config
    };
  }

  public async can(
    user: RbacUser,
    permission: PermissionFlag,
    resource: string,
    targetTenantId?: number
  ): Promise<boolean> {
    const decision = await this.authorize(user, permission, resource, targetTenantId);
    return decision.granted;
  }

  public async authorize(
    user: RbacUser,
    permission: PermissionFlag,
    resource: string,
    targetTenantId?: number
  ): Promise<RbacDecision> {
    const tTarget = targetTenantId ?? user.tenantId;

    // Enforce tenant isolation
    if (this.config.enforceTenantBoundary && user.tenantId !== tTarget) {
      // Unless admin role 3
      if (!user.roles.includes(3)) {
        return {
          granted: false,
          reason: 'Cross-tenant boundary violation',
          cached: false,
          evaluatedAt: Date.now()
        };
      }
    }

    const wasm = await WasmLoader.getInstance();
    const permMask = PERM_MAP[permission] || 1;

    for (const role of user.roles) {
      if (wasm.canAccess(role, resource, permMask)) {
        return {
          granted: true,
          reason: `Granted via role ${role}`,
          cached: false,
          evaluatedAt: Date.now()
        };
      }
    }

    return {
      granted: false,
      reason: `User lacks ${permission} permission for ${resource}`,
      cached: false,
      evaluatedAt: Date.now()
    };
  }
}

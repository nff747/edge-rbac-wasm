import { RbacUser, RbacDecision, PermissionFlag, EdgeRbacConfig } from './types.js';

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
    targetTenantId: number
  ): Promise<boolean> {
    const decision = await this.authorize(user, permission, resource, targetTenantId);
    return decision.granted;
  }

  public async authorize(
    user: RbacUser,
    permission: PermissionFlag,
    resource: string,
    targetTenantId: number
  ): Promise<RbacDecision> {
    if (!user || typeof user.id !== 'string' || !user.id.trim() || !Number.isSafeInteger(user.tenantId) || user.tenantId < 1 || !Array.isArray(user.roles) || !user.roles.length || user.roles.some(role => !Number.isSafeInteger(role) || role < 1 || role > 0xffffffff) || typeof resource !== 'string' || !resource.trim()) throw new Error('Invalid authorization request');
    if (!Number.isSafeInteger(targetTenantId) || targetTenantId! < 1) throw new Error('A trusted resource tenant is required');
    const tTarget = targetTenantId!;

    // Enforce tenant isolation
    if (this.config.enforceTenantBoundary && user.tenantId !== tTarget) {
        return {
          granted: false,
          reason: 'Cross-tenant boundary violation',
          cached: false,
          evaluatedAt: Date.now()
        };
    }

    const wasm = this.config.policyEngine;
    if (!wasm || typeof wasm.canAccess !== 'function') throw new Error('No authorization policy engine configured');
    const permMask = PERM_MAP[permission];
    if (!permMask) throw new Error('Unknown permission');

      if (wasm.canAccess(user.roles, resource, permMask)) {
        return {
          granted: true,
          reason: 'Granted by configured policy',
          cached: false,
          evaluatedAt: Date.now()
        };
      }

    return {
      granted: false,
      reason: `User lacks ${permission} permission for ${resource}`,
      cached: false,
      evaluatedAt: Date.now()
    };
  }
}

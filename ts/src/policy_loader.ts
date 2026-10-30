export interface DeclarativeRule {
  role: number;
  resource: string;
  permissions: string[];
  effect: 'allow' | 'deny';
}

export interface DeclarativePolicy {
  version: string;
  rules: DeclarativeRule[];
}

export class PolicySchemaParser {
  public static parse(jsonStr: string): DeclarativePolicy {
    const parsed = JSON.parse(jsonStr);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || !Array.isArray(parsed.rules)) {
      throw new Error('Policy schema error: missing rules array');
    }

    if (typeof parsed.version !== 'string' || !parsed.version.trim()) {
      throw new Error('Policy schema error: missing version');
    }

    const permissions = new Set(['read', 'write', 'delete', 'execute', 'admin', 'export', 'manage_users', 'manage_billing', 'audit_logs', 'impersonate']);

    for (const rule of parsed.rules) {
      if (!rule || typeof rule !== 'object' || !Number.isInteger(rule.role) || rule.role < 1 || rule.role > 0xffffffff ||
          typeof rule.resource !== 'string' || rule.resource.trim() !== rule.resource ||
          rule.resource.split(':').some((segment: string) => !segment || segment.trim() !== segment) ||
          rule.resource.split(':').slice(0, -1).includes('**') ||
          !Array.isArray(rule.permissions) || rule.permissions.length === 0 ||
          rule.permissions.some((permission: unknown) => typeof permission !== 'string' || !permissions.has(permission)) ||
          (rule.effect !== 'allow' && rule.effect !== 'deny')) {
        throw new Error('Policy schema error: invalid rule');
      }
    }

    return parsed;
  }
}

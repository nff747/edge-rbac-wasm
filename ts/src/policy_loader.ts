export interface DeclarativeRule {
  role: string | number;
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
    if (!parsed.rules || !Array.isArray(parsed.rules)) {
      throw new Error('Policy schema error: missing rules array');
    }

    for (const rule of parsed.rules) {
      if (!rule.resource || !rule.permissions || !rule.effect) {
        throw new Error('Policy schema error: rule missing required properties');
      }
    }

    return parsed;
  }
}

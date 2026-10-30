import { describe, it, expect } from 'vitest';
import { PolicySchemaParser } from '../src/policy_loader';

describe('PolicySchemaParser', () => {
  it('parses valid declarative policy document', () => {
    const raw = JSON.stringify({
      version: '1.0',
      rules: [
        { role: 1, resource: 'docs:*', permissions: ['read', 'write'], effect: 'allow' }
      ]
    });
    const policy = PolicySchemaParser.parse(raw);
    expect(policy.version).toBe('1.0');
    expect(policy.rules.length).toBe(1);
    expect(policy.rules[0].effect).toBe('allow');
  });

  it('throws error when rules array is missing or invalid', () => {
    expect(() => PolicySchemaParser.parse('{}')).toThrow('missing rules array');
    expect(() => PolicySchemaParser.parse('{"version":"1","rules": [{}]}')).toThrow('invalid rule');
  });

  it('rejects policies the WASM engine cannot safely apply', () => {
    const rule = { role: 1, resource: 'docs:**', permissions: ['read'], effect: 'allow' };
    for (const change of [{role: 'admin'}, {role: 0}, {resource: 'docs:**:secret'}, {resource: 'docs::secret'}, {permissions: ['unknown']}, {effect: 'maybe'}]) {
      expect(() => PolicySchemaParser.parse(JSON.stringify({version:'1', rules:[{...rule, ...change}]}))).toThrow('invalid rule');
    }
  });
});

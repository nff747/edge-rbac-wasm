import os
import subprocess
import sys

SCRATCH = "/home/n1khy/.gemini/antigravity/scratch/edge-rbac-wasm"

def run_cmd(cmd):
    res = subprocess.run(cmd, shell=True, cwd=SCRATCH, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"FAILED: {cmd}")
        print("STDOUT:", res.stdout)
        print("STDERR:", res.stderr)
        sys.exit(1)
    return res.stdout.strip()

def run_tests():
    res = subprocess.run("npm test", shell=True, cwd=SCRATCH, capture_output=True, text=True)
    if res.returncode != 0:
        print("NPM TESTS FAILED:")
        print(res.stdout)
        print(res.stderr)
        sys.exit(1)
    return True

def commit(msg):
    run_cmd("git add -A")
    out = run_cmd(f'git commit -m "{msg}"')
    print(f"Committed: {msg}")

# -------------------------------------------------------------
# Commit 41: test(policy-loader): add unit tests for policy loader
# -------------------------------------------------------------
policy_test = """import { describe, it, expect } from 'vitest';
import { PolicySchemaParser } from '../src/policy_loader';

describe('PolicySchemaParser', () => {
  it('parses valid declarative policy document', () => {
    const raw = JSON.stringify({
      version: '1.0',
      rules: [
        { role: 'editor', resource: 'docs:*', permissions: ['read', 'write'], effect: 'allow' }
      ]
    });
    const policy = PolicySchemaParser.parse(raw);
    expect(policy.version).toBe('1.0');
    expect(policy.rules.length).toBe(1);
    expect(policy.rules[0].effect).toBe('allow');
  });

  it('throws error when rules array is missing or invalid', () => {
    expect(() => PolicySchemaParser.parse('{}')).toThrow('missing rules array');
    expect(() => PolicySchemaParser.parse('{"rules": [{}]}')).toThrow('missing required properties');
  });
});
"""
with open(os.path.join(SCRATCH, "ts/tests/policy_loader.test.ts"), "w") as f:
    f.write(policy_test)

run_tests()
commit("test(policy-loader): add unit tests for declarative policy loading and schema parsing")

# -------------------------------------------------------------
# Commit 42: feat(memory-kv): implement edge in-memory KV cache adapter
# -------------------------------------------------------------
cache_adapter_ts = """export interface CacheEntry<T> {
  value: T;
  expiresAt: number;
}

export class EdgeMemoryCache<T = any> {
  private store: Map<string, CacheEntry<T>> = new Map();

  public get(key: string): T | null {
    const entry = this.store.get(key);
    if (!entry) return null;

    if (Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return null;
    }
    return entry.value;
  }

  public set(key: string, value: T, ttlMs: number = 60000): void {
    this.store.set(key, {
      value,
      expiresAt: Date.now() + ttlMs
    });
  }

  public delete(key: string): boolean {
    return this.store.delete(key);
  }

  public clear(): void {
    this.store.clear();
  }
}
"""
with open(os.path.join(SCRATCH, "ts/src/cache_adapter.ts"), "w") as f:
    f.write(cache_adapter_ts)

run_tests()
commit("feat(memory-kv): implement edge in-memory KV cache adapter with TTL invalidation")

# -------------------------------------------------------------
# Commit 43: test(memory-kv): add unit tests for edge cache adapter
# -------------------------------------------------------------
cache_adapter_test = """import { describe, it, expect } from 'vitest';
import { EdgeMemoryCache } from '../src/cache_adapter';

describe('EdgeMemoryCache', () => {
  it('stores and retrieves cached decision values', () => {
    const cache = new EdgeMemoryCache<boolean>();
    cache.set('key_1', true, 5000);
    expect(cache.get('key_1')).toBe(true);
    expect(cache.get('non_existent')).toBeNull();
  });

  it('evicts expired items based on TTL', () => {
    const cache = new EdgeMemoryCache<string>();
    cache.set('short_lived', 'val', -100); // Expired immediately
    expect(cache.get('short_lived')).toBeNull();
  });
});
"""
with open(os.path.join(SCRATCH, "ts/tests/cache_adapter.test.ts"), "w") as f:
    f.write(cache_adapter_test)

run_tests()
commit("test(memory-kv): add unit tests for edge cache adapter and invalidation triggers")

# -------------------------------------------------------------
# Commit 44: feat(errors): implement structured authorization errors
# -------------------------------------------------------------
errors_ts = """export class RbacError extends Error {
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
"""
with open(os.path.join(SCRATCH, "ts/src/errors.ts"), "w") as f:
    f.write(errors_ts)

run_tests()
commit("feat(errors): implement structured authorization errors with denial reason codes")

# -------------------------------------------------------------
# Commit 45: test(errors): add unit tests for error formatting
# -------------------------------------------------------------
errors_test = """import { describe, it, expect } from 'vitest';
import { PermissionDeniedError, TenantIsolationError } from '../src/errors';

describe('RbacError classes', () => {
  it('formats permission denial error with 403 status', () => {
    const err = new PermissionDeniedError('api:billing', 'write');
    expect(err.status).toBe(403);
    expect(err.code).toBe('PERMISSION_DENIED');
    expect(err.message).toContain('api:billing');

    const json = err.toJSON();
    expect(json.error).toBe('PermissionDeniedError');
  });

  it('formats cross-tenant isolation error with source and target IDs', () => {
    const err = new TenantIsolationError(100, 200);
    expect(err.code).toBe('TENANT_ISOLATION_VIOLATION');
    expect(err.message).toContain('source: 100, target: 200');
  });
});
"""
with open(os.path.join(SCRATCH, "ts/tests/errors.test.ts"), "w") as f:
    f.write(errors_test)

run_tests()
commit("test(errors): add unit tests for error formatting and HTTP 403 response bodies")

print("Block 9 (Commits 41-45) completed successfully.")

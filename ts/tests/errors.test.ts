import { describe, it, expect } from 'vitest';
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

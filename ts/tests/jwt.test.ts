import { describe, it, expect } from 'vitest';
import { EdgeJwtParser } from '../src/jwt';

describe('EdgeJwtParser', () => {
  function makeMockJwt(payload: object): string {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    return `${header}.${body}.mock_signature`;
  }

  it('decodes JWT claims and maps to RbacUser', () => {
    const token = makeMockJwt({
      sub: 'user_456',
      tenant_id: 101,
      roles: [2],
      exp: Math.floor(Date.now() / 1000) + 3600
    });

    const user = EdgeJwtParser.toRbacUser(token);
    expect(user.id).toBe('user_456');
    expect(user.tenantId).toBe(101);
    expect(user.roles).toEqual([2]);
  });

  it('throws error on expired token', () => {
    const expiredToken = makeMockJwt({
      sub: 'user_expired',
      exp: Math.floor(Date.now() / 1000) - 100
    });

    expect(() => EdgeJwtParser.toRbacUser(expiredToken)).toThrow('Token has expired');
  });
});

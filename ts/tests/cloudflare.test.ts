import { describe, it, expect } from 'vitest';
import { createCloudflareRbacMiddleware } from '../src/cloudflare';
import { EdgeRbacClient } from '../src/client';

describe('Cloudflare Workers Middleware', () => {
  const client = new EdgeRbacClient({policyEngine:{canAccess:(roles, _resource, permission) => roles.some(role => role === 3 || permission === 1 || role === 2 && permission === 2)}});
  const claims = new Map<string, { sub:string; tenant_id:number; roles:number[]; exp:number }>();
  const middleware = createCloudflareRbacMiddleware(client, async token => {
    const verified = claims.get(token); if (!verified) throw new Error('invalid signature'); return verified;
  });

  function makeMockJwt(payload: object): string {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256' })).toString('base64url');
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const token = `${header}.${body}.sig`;
    claims.set(token, { ...(payload as {sub:string;roles:number[]}), tenant_id:1, exp:Math.floor(Date.now()/1000)+60 });
    return token;
  }

  it('returns 401 if Authorization header is missing', async () => {
    const req = new Request('https://api.edge.dev/v1/data');
    const res = await middleware(req, 'read', 'api:data', 1);
    expect(res).not.toBeNull();
    expect(res?.status).toBe(401);
  });

  it('returns 403 if user lacks required permission', async () => {
    const token = makeMockJwt({ sub: 'u1', roles: [1] }); // Viewer
    const req = new Request('https://api.edge.dev/v1/data', {
      headers: { Authorization: `Bearer ${token}` }
    });

    const res = await middleware(req, 'delete', 'api:data', 1);
    expect(res?.status).toBe(403);
  });

  it('returns null (proceed) when user is authorized', async () => {
    const token = makeMockJwt({ sub: 'u2', roles: [2] }); // Editor
    const req = new Request('https://api.edge.dev/v1/data', {
      headers: { Authorization: `Bearer ${token}` }
    });

    const res = await middleware(req, 'write', 'api:data', 1);
    expect(res).toBeNull();
  });
  it('rejects a forged administrator token', async () => {
    const forged = `${Buffer.from('{}').toString('base64url')}.${Buffer.from(JSON.stringify({sub:'attacker',tenant_id:1,roles:[3],exp:Math.floor(Date.now()/1000)+60})).toString('base64url')}.forged`;
    expect((await middleware(new Request('https://api.edge.dev/', {headers:{Authorization:`Bearer ${forged}`}}), 'admin', 'api:data', 1))?.status).toBe(401);
  });
  it('fails closed without a verifier', () => expect(() => createCloudflareRbacMiddleware(client, undefined as any)).toThrow('verifier'));
});

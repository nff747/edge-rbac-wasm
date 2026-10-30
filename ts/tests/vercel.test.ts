import { describe, it, expect } from 'vitest';
import { createVercelEdgeHandler } from '../src/vercel';
import { EdgeRbacClient } from '../src/client';

describe('Vercel Edge Handler', () => {
  const client = new EdgeRbacClient({policyEngine:{canAccess:(roles, _resource, permission) => roles.some(role => role === 3 || permission === 1 || role === 2 && permission === 2)}});
  const claims = new Map<string, { sub:string; tenant_id:number; roles:number[]; exp:number }>();
  const handler = createVercelEdgeHandler(client, async token => {
    const verified = claims.get(token); if (!verified) throw new Error('invalid signature'); return verified;
  });

  function makeMockJwt(payload: object): string {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256' })).toString('base64url');
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const token = `${header}.${body}.sig`;
    claims.set(token, { ...(payload as {sub:string;roles:number[]}), tenant_id:1, exp:Math.floor(Date.now()/1000)+60 });
    return token;
  }

  it('authorizes valid requests and returns userId', async () => {
    const token = makeMockJwt({ sub: 'user_admin', roles: [3] });
    const req = new Request('https://vercel.app/api/admin', {
      headers: { authorization: `Bearer ${token}` }
    });

    const result = await handler(req, 'admin', 'admin:system', 1);
    expect(result.authorized).toBe(true);
    expect(result.userId).toBe('user_admin');
  });

  it('rejects unauthorized requests with 403 Response', async () => {
    const token = makeMockJwt({ sub: 'user_viewer', roles: [1] });
    const req = new Request('https://vercel.app/api/admin', {
      headers: { authorization: `Bearer ${token}` }
    });

    const result = await handler(req, 'admin', 'admin:system', 1);
    expect(result.authorized).toBe(false);
    expect(result.response?.status).toBe(403);
  });
  it('rejects forged credentials', async () => {
    const result = await handler(new Request('https://vercel.app/', {headers:{authorization:'Bearer forged.token.signature'}}), 'admin', 'admin:system', 1);
    expect(result.authorized).toBe(false); expect(result.response?.status).toBe(401);
  });
  it('fails closed without a verifier', () => expect(() => createVercelEdgeHandler(client, undefined as any)).toThrow('verifier'));
});

import { describe, it, expect } from 'vitest';
import { createVercelEdgeHandler } from '../src/vercel';
import { EdgeRbacClient } from '../src/client';

describe('Vercel Edge Handler', () => {
  const client = new EdgeRbacClient();
  const handler = createVercelEdgeHandler(client);

  function makeMockJwt(payload: object): string {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256' })).toString('base64url');
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    return `${header}.${body}.sig`;
  }

  it('authorizes valid requests and returns userId', async () => {
    const token = makeMockJwt({ sub: 'user_admin', roles: [3] });
    const req = new Request('https://vercel.app/api/admin', {
      headers: { authorization: `Bearer ${token}` }
    });

    const result = await handler(req, 'admin', 'admin:system');
    expect(result.authorized).toBe(true);
    expect(result.userId).toBe('user_admin');
  });

  it('rejects unauthorized requests with 403 Response', async () => {
    const token = makeMockJwt({ sub: 'user_viewer', roles: [1] });
    const req = new Request('https://vercel.app/api/admin', {
      headers: { authorization: `Bearer ${token}` }
    });

    const result = await handler(req, 'admin', 'admin:system');
    expect(result.authorized).toBe(false);
    expect(result.response?.status).toBe(403);
  });
});

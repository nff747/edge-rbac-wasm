import { describe, it, expect } from 'vitest';
import { createCloudflareRbacMiddleware } from '../src/cloudflare';
import { EdgeRbacClient } from '../src/client';

describe('Cloudflare Workers Middleware', () => {
  const client = new EdgeRbacClient();
  const middleware = createCloudflareRbacMiddleware(client);

  function makeMockJwt(payload: object): string {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256' })).toString('base64url');
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    return `${header}.${body}.sig`;
  }

  it('returns 401 if Authorization header is missing', async () => {
    const req = new Request('https://api.edge.dev/v1/data');
    const res = await middleware(req, 'read', 'api:data');
    expect(res).not.toBeNull();
    expect(res?.status).toBe(401);
  });

  it('returns 403 if user lacks required permission', async () => {
    const token = makeMockJwt({ sub: 'u1', roles: [1] }); // Viewer
    const req = new Request('https://api.edge.dev/v1/data', {
      headers: { Authorization: `Bearer ${token}` }
    });

    const res = await middleware(req, 'delete', 'api:data');
    expect(res?.status).toBe(403);
  });

  it('returns null (proceed) when user is authorized', async () => {
    const token = makeMockJwt({ sub: 'u2', roles: [2] }); // Editor
    const req = new Request('https://api.edge.dev/v1/data', {
      headers: { Authorization: `Bearer ${token}` }
    });

    const res = await middleware(req, 'write', 'api:data');
    expect(res).toBeNull();
  });
});

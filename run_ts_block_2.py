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
# Commit 31: test(client): add unit tests for fluent authorization client
# -------------------------------------------------------------
client_test = """import { describe, it, expect } from 'vitest';
import { EdgeRbacClient } from '../src/client';
import { RbacUser } from '../src/types';

describe('EdgeRbacClient', () => {
  const client = new EdgeRbacClient();

  const viewerUser: RbacUser = {
    id: 'user_1',
    tenantId: 100,
    roles: [1]
  };

  const editorUser: RbacUser = {
    id: 'user_2',
    tenantId: 100,
    roles: [2]
  };

  it('verifies permissions for standard roles', async () => {
    expect(await client.can(viewerUser, 'read', 'api:docs')).toBe(true);
    expect(await client.can(viewerUser, 'write', 'api:docs')).toBe(false);

    expect(await client.can(editorUser, 'read', 'api:docs')).toBe(true);
    expect(await client.can(editorUser, 'write', 'api:docs')).toBe(true);
  });

  it('enforces tenant boundary isolation', async () => {
    // Editor in tenant 100 cannot access tenant 200
    const decision = await client.authorize(editorUser, 'read', 'api:docs', 200);
    expect(decision.granted).toBe(false);
    expect(decision.reason).toContain('Cross-tenant boundary violation');
  });
});
"""
with open(os.path.join(SCRATCH, "ts/tests/client.test.ts"), "w") as f:
    f.write(client_test)

run_tests()
commit("test(client): add unit tests for fluent authorization client and role checks")

# -------------------------------------------------------------
# Commit 32: feat(jwt): implement zero-dependency edge JWT claims extractor
# -------------------------------------------------------------
jwt_ts = """import { RbacUser } from './types';

export interface JwtClaims {
  sub: string;
  tenant_id?: number;
  roles?: number[];
  exp?: number;
  [key: string]: any;
}

export class EdgeJwtParser {
  public static decodeUnverified(token: string): JwtClaims {
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWT format');
    }

    const payload = parts[1];
    // Base64Url decode in Edge / Node
    const base64 = payload.replace(/-/g, '+').replace(/_/g, '/');
    const jsonStr = Buffer.from(base64, 'base64').toString('utf-8');
    return JSON.parse(jsonStr);
  }

  public static toRbacUser(token: string): RbacUser {
    const claims = this.decodeUnverified(token);

    if (claims.exp && claims.exp * 1000 < Date.now()) {
      throw new Error('Token has expired');
    }

    return {
      id: claims.sub,
      tenantId: claims.tenant_id ?? 1,
      roles: claims.roles ?? [1], // Default viewer
      attributes: {
        email: claims.email || '',
        sub: claims.sub
      }
    };
  }
}
"""
with open(os.path.join(SCRATCH, "ts/src/jwt.ts"), "w") as f:
    f.write(jwt_ts)

run_tests()
commit("feat(jwt): implement zero-dependency edge JWT claims extractor and role mapper")

# -------------------------------------------------------------
# Commit 33: test(jwt): add unit tests for JWT parsing
# -------------------------------------------------------------
jwt_test = """import { describe, it, expect } from 'vitest';
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
"""
with open(os.path.join(SCRATCH, "ts/tests/jwt.test.ts"), "w") as f:
    f.write(jwt_test)

run_tests()
commit("test(jwt): add unit tests for JWT parsing, expiry validation, and claim extraction")

# -------------------------------------------------------------
# Commit 34: feat(cloudflare): implement native Cloudflare Workers middleware adapter
# -------------------------------------------------------------
cf_ts = """import { EdgeRbacClient } from './client';
import { EdgeJwtParser } from './jwt';
import { PermissionFlag } from './types';

export function createCloudflareRbacMiddleware(client: EdgeRbacClient) {
  return async (
    request: Request,
    requiredPermission: PermissionFlag,
    resource: string
  ): Promise<Response | null> => {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return new Response(JSON.stringify({ error: 'Missing or invalid Authorization header' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    try {
      const token = authHeader.slice(7);
      const user = EdgeJwtParser.toRbacUser(token);
      const decision = await client.authorize(user, requiredPermission, resource);

      if (!decision.granted) {
        return new Response(JSON.stringify({ error: 'Forbidden', reason: decision.reason }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      return null; // Authorized, proceed to handler
    } catch (err: any) {
      return new Response(JSON.stringify({ error: err.message }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  };
}
"""
with open(os.path.join(SCRATCH, "ts/src/cloudflare.ts"), "w") as f:
    f.write(cf_ts)

run_tests()
commit("feat(cloudflare): implement native Cloudflare Workers middleware adapter")

# -------------------------------------------------------------
# Commit 35: test(cloudflare): add unit tests for Cloudflare Workers request interception
# -------------------------------------------------------------
cf_test = """import { describe, it, expect } from 'vitest';
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
"""
with open(os.path.join(SCRATCH, "ts/tests/cloudflare.test.ts"), "w") as f:
    f.write(cf_test)

run_tests()
commit("test(cloudflare): add unit tests for Cloudflare Workers request interception")

print("Block 7 (Commits 31-35) completed successfully.")

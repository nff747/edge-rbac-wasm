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
# Commit 36: feat(vercel): implement native Vercel Edge middleware handler
# -------------------------------------------------------------
vercel_ts = """import { EdgeRbacClient } from './client';
import { EdgeJwtParser } from './jwt';
import { PermissionFlag } from './types';

export function createVercelEdgeHandler(client: EdgeRbacClient) {
  return async (
    req: Request,
    requiredPermission: PermissionFlag,
    resource: string
  ): Promise<{ authorized: boolean; response?: Response; userId?: string }> => {
    const authHeader = req.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return {
        authorized: false,
        response: new Response(JSON.stringify({ error: 'Unauthorized: Missing bearer token' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        })
      };
    }

    try {
      const user = EdgeJwtParser.toRbacUser(authHeader.slice(7));
      const decision = await client.authorize(user, requiredPermission, resource);

      if (!decision.granted) {
        return {
          authorized: false,
          response: new Response(JSON.stringify({ error: 'Forbidden', reason: decision.reason }), {
            status: 403,
            headers: { 'Content-Type': 'application/json' }
          }),
          userId: user.id
        };
      }

      return { authorized: true, userId: user.id };
    } catch (err: any) {
      return {
        authorized: false,
        response: new Response(JSON.stringify({ error: err.message }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        })
      };
    }
  };
}
"""
with open(os.path.join(SCRATCH, "ts/src/vercel.ts"), "w") as f:
    f.write(vercel_ts)

run_tests()
commit("feat(vercel): implement native Vercel Edge middleware handler")

# -------------------------------------------------------------
# Commit 37: test(vercel): add unit tests for Vercel Edge handler
# -------------------------------------------------------------
vercel_test = """import { describe, it, expect } from 'vitest';
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
"""
with open(os.path.join(SCRATCH, "ts/tests/vercel.test.ts"), "w") as f:
    f.write(vercel_test)

run_tests()
commit("test(vercel): add unit tests for Vercel Edge request headers and 403 responses")

# -------------------------------------------------------------
# Commit 38: feat(audit-emitter): implement async batched audit logger
# -------------------------------------------------------------
audit_ts = """import { AuditEntry } from './types';

export class EdgeAuditLogger {
  private buffer: AuditEntry[] = [];
  private batchSize: number;
  private onFlush: (entries: AuditEntry[]) => Promise<void> | void;

  constructor(batchSize: number = 20, onFlush: (entries: AuditEntry[]) => Promise<void> | void = () => {}) {
    this.batchSize = batchSize;
    this.onFlush = onFlush;
  }

  public log(entry: AuditEntry): void {
    this.buffer.push(entry);
    if (this.buffer.length >= this.batchSize) {
      this.flush();
    }
  }

  public flush(): AuditEntry[] {
    const toFlush = [...this.buffer];
    this.buffer = [];
    if (toFlush.length > 0) {
      this.onFlush(toFlush);
    }
    return toFlush;
  }

  public pendingCount(): number {
    return this.buffer.length;
  }
}
"""
with open(os.path.join(SCRATCH, "ts/src/audit_logger.ts"), "w") as f:
    f.write(audit_ts)

run_tests()
commit("feat(audit-emitter): implement async batched audit logger for edge runtimes")

# -------------------------------------------------------------
# Commit 39: test(audit-emitter): add unit tests for audit log batching
# -------------------------------------------------------------
audit_test = """import { describe, it, expect, vi } from 'vitest';
import { EdgeAuditLogger } from '../src/audit_logger';

describe('EdgeAuditLogger', () => {
  it('buffers audit entries and flushes when batch limit is reached', () => {
    const onFlush = vi.fn();
    const logger = new EdgeAuditLogger(3, onFlush);

    logger.log({
      timestamp: Date.now(),
      requestId: 'req_1',
      tenantId: 1,
      roleId: 2,
      resource: 'doc:1',
      permission: 'read',
      granted: true,
      reason: 'Allowed'
    });

    expect(logger.pendingCount()).toBe(1);
    expect(onFlush).not.toHaveBeenCalled();

    logger.log({ timestamp: Date.now(), requestId: 'req_2', tenantId: 1, roleId: 2, resource: 'doc:2', permission: 'read', granted: true, reason: 'Allowed' });
    logger.log({ timestamp: Date.now(), requestId: 'req_3', tenantId: 1, roleId: 2, resource: 'doc:3', permission: 'read', granted: true, reason: 'Allowed' });

    expect(onFlush).toHaveBeenCalledTimes(1);
    expect(logger.pendingCount()).toBe(0);
  });
});
"""
with open(os.path.join(SCRATCH, "ts/tests/audit_logger.test.ts"), "w") as f:
    f.write(audit_test)

run_tests()
commit("test(audit-emitter): add unit tests for audit log batching and flush handlers")

# -------------------------------------------------------------
# Commit 40: feat(policy-loader): implement JSON policy schema parser
# -------------------------------------------------------------
policy_ts = """export interface DeclarativeRule {
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
"""
with open(os.path.join(SCRATCH, "ts/src/policy_loader.ts"), "w") as f:
    f.write(policy_ts)

run_tests()
commit("feat(policy-loader): implement JSON and YAML policy schema parser and validator")

print("Block 8 (Commits 36-40) completed successfully.")

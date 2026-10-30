import { EdgeRbacClient } from './client.js';
import { RbacUser } from './types.js';
import type { PolicyEngine } from './wasm_loader.js';

export async function runAuthorizationBenchmark(iterations: number, policyEngine: PolicyEngine): Promise<{
  opsPerSec: number;
  avgLatencyUs: number;
  durationMs: number;
}> {
  const client = new EdgeRbacClient({ policyEngine });
  const user: RbacUser = {
    id: 'bench_user',
    tenantId: 10,
    roles: [2]
  };

  const start = performance.now();
  for (let i = 0; i < iterations; i++) {
    await client.can(user, 'read', 'api:v1:data', 10);
  }
  const durationMs = performance.now() - start;
  const avgLatencyUs = (durationMs / iterations) * 1000;
  const opsPerSec = Math.round(iterations / (durationMs / 1000));

  return { opsPerSec, avgLatencyUs, durationMs };
}

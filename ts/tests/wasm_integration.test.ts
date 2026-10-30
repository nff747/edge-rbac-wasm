import { createRequire } from 'node:module';
import { describe, it, expect } from 'vitest';
import { EdgeRbacClient } from '../src/client';
import { adaptWasmPolicy } from '../src/wasm_loader';
import { createJwtVerifier } from '../src/jwt';
import { createCloudflareRbacMiddleware } from '../src/cloudflare';
import { randomBytes } from 'node:crypto';
import { SignJWT } from 'jose';

const wasmPath = process.env.EDGE_RBAC_WASM_TEST_PATH;
describe.skipIf(!wasmPath)('compiled Rust WASM policy adapter', () => {
  it('uses actual WASM decisions and still enforces tenant boundaries', async () => {
    const require = createRequire(import.meta.url);
    const { WasmEdgeRbac } = require(wasmPath!);
    const engine = new WasmEdgeRbac();
    try {
      engine.add_rule('read', 1, 'api:**', 1, true);
      engine.add_rule('deny-read', 2, 'api:secret', 1, false);
      const client = new EdgeRbacClient({ policyEngine: adaptWasmPolicy(engine) });
      const viewer = { id: 'viewer', tenantId: 1, roles: [1] };
      expect(await client.can(viewer, 'read', 'api:docs', 1)).toBe(true);
      expect(await client.can(viewer, 'write', 'api:docs', 1)).toBe(false);
      expect(await client.can({ ...viewer, roles: [1,2] }, 'read', 'api:secret', 1)).toBe(false);
      expect(await client.can({ ...viewer, roles: [3] }, 'admin', 'api:docs', 2)).toBe(false);
    } finally { engine.free(); }
  });
  it('requires a signed identity and denies a different resource tenant', async () => {
    const { WasmEdgeRbac } = createRequire(import.meta.url)(wasmPath!);
    const engine = new WasmEdgeRbac();
    try {
      engine.add_rule('admin', 3, '**', 16, true);
      const key = randomBytes(32);
      const token = await new SignJWT({tenant_id:1,roles:[3]}).setProtectedHeader({alg:'HS256'}).setSubject('fixture').setIssuer('https://issuer.example').setAudience('test-api').setExpirationTime('5m').sign(key);
      const verifier = createJwtVerifier({key,issuer:'https://issuer.example',audience:'test-api',algorithms:['HS256']});
      const middleware = createCloudflareRbacMiddleware(new EdgeRbacClient({policyEngine:adaptWasmPolicy(engine)}), verifier);
      const request = new Request('https://local.test/',{headers:{authorization:`Bearer ${token}`}});
      expect(await middleware(request,'admin','docs',1)).toBeNull();
      expect((await middleware(request,'admin','docs',2))?.status).toBe(403);
    } finally { engine.free(); }
  });
});

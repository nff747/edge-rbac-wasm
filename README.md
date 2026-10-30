# edge-rbac-wasm

An experimental Rust/WebAssembly role-based authorization engine with TypeScript adapters. This work is **not yet production-ready**: it needs independent security review and testing on the intended edge runtimes. Earlier versions trusted unverified JWT claims and included a permissive mock policy; do not rely on those versions for authorization. The revised API is breaking.

## Security model

- JWT middleware requires a verifier. `createJwtVerifier` checks a signature with a trusted key, a configured issuer, audience and algorithm allowlist, and validates required identity claims. Key provisioning, rotation and identity-provider configuration are the application's responsibility. `decodeUnverified` must never make an access decision.
- An engine starts with **no rules** and denies access by default. Configure rules from trusted application data; do not let untrusted users edit the policy.
- Explicit deny takes precedence across all effective roles. Role inheritance rejects cycles and excessive depth.
- The caller must resolve the target resource's tenant from trusted server-side data and pass it to the middleware or client. Reading the target tenant from the requester's token does not establish ownership. Tenant isolation is enabled by default; disabling it transfers that responsibility entirely to the application.
- Authorization is a local decision, not a substitute for verifying identity, checking resource ownership, safe policy administration, logging, or a security review.

## Build and test locally

```sh
npm install
npm run build       # requires Rust and wasm-pack
npm test
cargo test
```

The npm build outputs JavaScript, declarations and a web-targeted WASM module under `dist/`. The optional WASM integration tests use a separately built Node-targeted module:

```sh
wasm-pack build --target nodejs --dev --out-dir /tmp/edge-rbac-node
EDGE_RBAC_WASM_TEST_PATH=/tmp/edge-rbac-node/edge_rbac_wasm.js npm test
```

## Configure a policy

Initialize the generated WebAssembly module according to the requirements of your runtime, then add reviewed rules before serving requests. For example, after initialization:

```ts
import { WasmEdgeRbac } from 'edge-rbac-wasm/wasm';
import { EdgeRbacClient, adaptWasmPolicy } from 'edge-rbac-wasm';

const engine = new WasmEdgeRbac();
engine.add_rule('document-read', 1, 'documents:**', 1, true);
engine.add_rule('restricted-deny', 2, 'documents:restricted', 1, false);
const client = new EdgeRbacClient({ policyEngine: adaptWasmPolicy(engine) });

// `principal` must come from verified identity claims. The target tenant
// must come from the actual resource record, not the requester's token.
const allowed = await client.can(principal, 'read', resourceName, resourceTenantId);
```

This is an integration sketch: `principal`, `resourceName`, and `resourceTenantId` are application data, not built-in identities. The example grants role 1 read access; a matching deny for role 2 wins when both roles apply. Review every rule for your own resource naming scheme.

For middleware, construct `createJwtVerifier` with the identity provider's trusted verification key, issuer, audience and allowed algorithms, then pass it with the client to `createCloudflareRbacMiddleware` or `createVercelEdgeHandler`. Each authorization call requires a trusted target tenant ID. The returned denial must be honored before accessing the resource.

The `edge-rbac validate` CLI checks the shape of a JSON policy; **it does not load or apply the policy**. Application code must translate validated policy data into engine rules using trusted configuration.

## Limitations

The packaged module and signed-token-to-WASM path have been exercised in local Node tests; Cloudflare, Vercel, browsers, production key rotation, sustained performance, and real deployment configurations have not been verified by those tests. No latency, device compatibility, or security certification is guaranteed. Treat the system as experimental until independently audited and tested in your deployment.

## License

[Apache License 2.0](LICENSE).

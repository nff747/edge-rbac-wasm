# 🛡️ edge-rbac-wasm

> **Ultra-fast, stateless Authorization and Multi-Tenancy engine compiled to WebAssembly for Cloudflare Workers, Vercel Edge, and Node.js runtimes.**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Rust_Tests-100%25_Passing-brightgreen.svg)]()
[![Vitest](https://img.shields.io/badge/Vitest-100%25_Passing-brightgreen.svg)]()
[![Throughput](https://img.shields.io/badge/Latency-%3C1%CE%BCs-blueviolet.svg)]()

---

## ⚡ The Problem
B2B SaaS applications spend weeks writing repetitive, bug-prone Role-Based Access Control (RBAC) and Multi-Tenancy isolation logic. Existing solutions (like OPA/Rego) are heavy, require centralized network roundtrips, or lack native support for edge runtimes like Cloudflare Workers and Vercel Edge Functions.

## 🛡️ The Solution
`edge-rbac-wasm` combines the speed of **Rust compiled to WASM** with edge-native TypeScript bindings:
1. **Microsecond Latency**: Pure bitmask permission calculations (`u32` bitflags) evaluating in `< 1μs`.
2. **Role Graph & Cycle Detection**: Directed Acyclic Graph (DAG) for role inheritance with cycle rejection.
3. **Strict Multi-Tenant Isolation**: Hard boundaries between tenant resources with organizational parent-child hierarchies.
4. **Declarative Policies**: Policy-as-Code with **Explicit Deny** precedence over Allow rules.
5. **Contextual ABAC**: Dynamic attribute condition evaluations (IP, environment, department).
6. **Zero-Roundtrip Edge Middlewares**: Drop-in middleware for Cloudflare Workers and Vercel Edge.

---

## 🚀 Quick Start

### Installation
```bash
npm install edge-rbac-wasm
```

### 1. Cloudflare Workers Middleware
```typescript
import { EdgeRbacClient, createCloudflareRbacMiddleware } from 'edge-rbac-wasm';

const client = new EdgeRbacClient({ enforceTenantBoundary: true });
const rbacMiddleware = createCloudflareRbacMiddleware(client);

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Intercepts request, decodes JWT, verifies permissions
    const denial = await rbacMiddleware(request, 'write', 'documents:financials');
    if (denial) return denial; // Returns 401/403 automatically if unauthorized

    return new Response('Access Granted!');
  }
};
```

### 2. Vercel Edge Middleware
```typescript
import { EdgeRbacClient, createVercelEdgeHandler } from 'edge-rbac-wasm';

const client = new EdgeRbacClient();
const authorize = createVercelEdgeHandler(client);

export async function middleware(req: Request) {
  const result = await authorize(req, 'admin', 'api:system:config');
  if (!result.authorized) {
    return result.response!;
  }
  return new Response('Welcome Admin ' + result.userId);
}
```

---

## 🏗️ Architecture Matrix

```
       Incoming HTTP Request (Bearer JWT)
                       │
                       ▼
             [ EdgeJwtParser ]
                       │
          ┌────────────┴────────────┐
          ▼                         ▼
   Tenant Boundary Check     Decision Cache (LRU)
          │                         │
          ▼                         ▼ (Miss)
    [ RoleGraph DAG ] ──────► [ PolicyDocument ]
          │                         │
          ▼                         ▼
   Bitmask Evaluation        ABAC Conditions (IP, Env)
          │                         │
          └────────────┬────────────┘
                       ▼
               Decision: ALLOW/DENY
                       │
                       ├─► Return 200 / 403 Forbidden
                       └─► Asynchronous EdgeAuditLogger
```

---

## 🧪 Testing & Verification

### Rust Core
```bash
cargo test
# All 11 test suites and 21 integration tests pass in 0.01s
```

### TypeScript Edge Layer
```bash
npm test
# All 10 vitest test suites pass
```

---

## 📄 License
Licensed under the [Apache License, Version 2.0](LICENSE).

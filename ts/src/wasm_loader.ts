/** Explicit policy adapter. It must be initialized with reviewed rules by the application. */
export interface PolicyEngine {
  canAccess(roles: number[], resource: string, permissionMask: number): boolean;
}

/** Adapt an initialized wasm-bindgen WasmEdgeRbac instance. */
export function adaptWasmPolicy(engine: { can_access_roles(roles: Uint32Array, resource: string, permissionMask: number): boolean }): PolicyEngine {
  if (!engine || typeof engine.can_access_roles !== 'function') throw new Error('An initialized WASM policy engine is required');
  return { canAccess: (roles, resource, mask) => engine.can_access_roles(Uint32Array.from(roles), resource, mask) };
}

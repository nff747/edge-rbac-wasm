import { describe, it, expect } from 'vitest';
import { adaptWasmPolicy } from '../src/wasm_loader';

describe('explicit WASM adapter', () => {
  it('forwards to the supplied engine rather than inventing a policy', () => {
    const calls: unknown[][] = [];
    const policy = adaptWasmPolicy({can_access_roles: (...args) => { calls.push([Array.from(args[0]), args[1], args[2]]); return false; }});
    expect(policy.canAccess([3, 4], 'secret', 4)).toBe(false);
    expect(calls).toEqual([[[3, 4], 'secret', 4]]);
  });
  it('rejects an uninitialized engine', () => expect(() => adaptWasmPolicy(null as any)).toThrow());
});

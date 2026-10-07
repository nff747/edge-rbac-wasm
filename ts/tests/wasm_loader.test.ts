import { describe, it, expect, beforeEach } from 'vitest';
import { WasmLoader } from '../src/wasm_loader';

describe('WasmLoader', () => {
  beforeEach(() => {
    WasmLoader.reset();
  });

  it('loads and caches single isomorphic WASM engine instance', async () => {
    const inst1 = await WasmLoader.getInstance();
    const inst2 = await WasmLoader.getInstance();
    expect(inst1).toBe(inst2);
  });

  it('evaluates role access matching WASM engine specification', async () => {
    const inst = await WasmLoader.getInstance();
    // Viewer (1) can read (1), cannot write (2)
    expect(inst.canAccess(1, 'api:feed', 1)).toBe(true);
    expect(inst.canAccess(1, 'api:feed', 2)).toBe(false);

    // Admin (3) can perform any action
    expect(inst.canAccess(3, 'admin:settings', 4)).toBe(true);
  });
});

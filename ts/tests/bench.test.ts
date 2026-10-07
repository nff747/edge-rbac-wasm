import { describe, it, expect } from 'vitest';
import { runAuthorizationBenchmark } from '../src/benchmarks';

describe('Performance Benchmarks', () => {
  it('executes thousands of decisions in milliseconds', async () => {
    const res = await runAuthorizationBenchmark(1000);
    expect(res.durationMs).toBeLessThan(100);
    expect(res.opsPerSec).toBeGreaterThan(10000);
  });
});

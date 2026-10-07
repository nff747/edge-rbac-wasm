import { describe, it, expect } from 'vitest';
import { EdgeMemoryCache } from '../src/cache_adapter';

describe('EdgeMemoryCache', () => {
  it('stores and retrieves cached decision values', () => {
    const cache = new EdgeMemoryCache<boolean>();
    cache.set('key_1', true, 5000);
    expect(cache.get('key_1')).toBe(true);
    expect(cache.get('non_existent')).toBeNull();
  });

  it('evicts expired items based on TTL', () => {
    const cache = new EdgeMemoryCache<string>();
    cache.set('short_lived', 'val', -100); // Expired immediately
    expect(cache.get('short_lived')).toBeNull();
  });
});

export interface CacheEntry<T> {
  value: T;
  expiresAt: number;
}

export class EdgeMemoryCache<T = any> {
  private store: Map<string, CacheEntry<T>> = new Map();

  public get(key: string): T | null {
    const entry = this.store.get(key);
    if (!entry) return null;

    if (Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return null;
    }
    return entry.value;
  }

  public set(key: string, value: T, ttlMs: number = 60000): void {
    this.store.set(key, {
      value,
      expiresAt: Date.now() + ttlMs
    });
  }

  public delete(key: string): boolean {
    return this.store.delete(key);
  }

  public clear(): void {
    this.store.clear();
  }
}

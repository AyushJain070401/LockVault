import { KeyValueStore } from '../types/index.js';

/**
 * Default in-memory key-value store with TTL support.
 *
 * Works for single-instance deployments. For multi-instance or serverless
 * setups, provide a Redis-backed or database-backed KeyValueStore.
 */
export class MemoryKeyValueStore implements KeyValueStore {
  private store = new Map<string, { value: string; expiresAt?: number }>();
  private cleanupTimer?: ReturnType<typeof setInterval>;
  private readonly maxEntries: number;

  constructor(options: { maxEntries?: number; cleanupIntervalMs?: number } = {}) {
    this.maxEntries = options.maxEntries ?? 50_000;
    // Periodic cleanup every 60 seconds
    this.cleanupTimer = setInterval(() => this.cleanup(), options.cleanupIntervalMs ?? 60_000);
    if (this.cleanupTimer.unref) {
      this.cleanupTimer.unref();
    }
  }

  async get(key: string): Promise<string | null> {
    const entry = this.store.get(key);
    if (!entry) return null;
    if (entry.expiresAt && entry.expiresAt < Date.now()) {
      this.store.delete(key);
      return null;
    }
    return entry.value;
  }

  async set(key: string, value: string, ttlMs?: number): Promise<void> {
    // Evict if over capacity
    if (this.store.size >= this.maxEntries) {
      this.cleanup();
      if (this.store.size >= this.maxEntries) {
        // Evict oldest entries
        const toRemove = this.store.size - this.maxEntries + 1;
        const keys = this.store.keys();
        for (let i = 0; i < toRemove; i++) {
          const k = keys.next().value;
          if (k) this.store.delete(k);
        }
      }
    }

    this.store.set(key, {
      value,
      expiresAt: ttlMs ? Date.now() + ttlMs : undefined,
    });
  }

  async delete(key: string): Promise<boolean> {
    return this.store.delete(key);
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.store) {
      if (entry.expiresAt && entry.expiresAt < now) {
        this.store.delete(key);
      }
    }
  }

  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = undefined;
    }
    this.store.clear();
  }
}

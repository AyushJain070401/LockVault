import { KeyValueStore } from '../types/index.js';

/**
 * Create an in-memory key-value store with TTL support.
 */
export function createMemoryKeyValueStore(
  options: { maxEntries?: number; cleanupIntervalMs?: number } = {},
): KeyValueStore & { destroy(): void } {
  const maxEntries = options.maxEntries ?? 50_000;
  const store = new Map<string, { value: string; expiresAt?: number }>();

  function cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of store) {
      if (entry.expiresAt && entry.expiresAt < now) store.delete(key);
    }
  }

  let cleanupTimer: ReturnType<typeof setInterval> | undefined = setInterval(
    () => cleanup(),
    options.cleanupIntervalMs ?? 60_000,
  );
  if (cleanupTimer.unref) cleanupTimer.unref();

  return {
    async get(key: string): Promise<string | null> {
      const entry = store.get(key);
      if (!entry) return null;
      if (entry.expiresAt && entry.expiresAt < Date.now()) { store.delete(key); return null; }
      return entry.value;
    },
    async set(key: string, value: string, ttlMs?: number): Promise<void> {
      if (store.size >= maxEntries) {
        cleanup();
        if (store.size >= maxEntries) {
          const toRemove = store.size - maxEntries + 1;
          const keys = store.keys();
          for (let i = 0; i < toRemove; i++) { const k = keys.next().value; if (k) store.delete(k); }
        }
      }
      store.set(key, { value, expiresAt: ttlMs ? Date.now() + ttlMs : undefined });
    },
    async delete(key: string): Promise<boolean> { return store.delete(key); },
    destroy(): void {
      if (cleanupTimer) { clearInterval(cleanupTimer); cleanupTimer = undefined; }
      store.clear();
    },
  };
}

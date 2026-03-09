import { AuthErrorCode } from '../types/index.js';
import { LockVaultError } from '../utils/errors.js';

export class RateLimitError extends LockVaultError {
  public readonly retryAfterMs: number;
  constructor(identifier: string, retryAfterMs: number) {
    super(`Rate limit exceeded for "${identifier}". Retry after ${Math.ceil(retryAfterMs / 1000)}s.`, AuthErrorCode.RATE_LIMITED, 429, { identifier, retryAfterMs });
    this.name = 'RateLimitError';
    this.retryAfterMs = retryAfterMs;
    Object.setPrototypeOf(this, RateLimitError.prototype);
  }
}

export interface RateLimiterConfig {
  windowMs: number;
  maxAttempts: number;
  onRateLimit?: (identifier: string) => void | Promise<void>;
}

export interface RateLimiter {
  consume(identifier: string): Promise<void>;
  reset(identifier: string): void;
  remaining(identifier: string): number;
  cleanup(): void;
  destroy(): void;
}

export function createRateLimiter(config: Partial<RateLimiterConfig> = {}): RateLimiter {
  const windowMs = config.windowMs ?? 60_000;
  const maxAttempts = config.maxAttempts ?? 5;
  const onRateLimit = config.onRateLimit;
  const store = new Map<string, { timestamps: number[] }>();

  let cleanupTimer: ReturnType<typeof setInterval> | undefined = setInterval(() => cleanup(), 300_000);
  if (cleanupTimer?.unref) cleanupTimer.unref();

  function cleanup(): void {
    const now = Date.now();
    const windowStart = now - windowMs;
    for (const [key, entry] of store) {
      entry.timestamps = entry.timestamps.filter(t => t > windowStart);
      if (entry.timestamps.length === 0) store.delete(key);
    }
  }

  return {
    async consume(identifier: string): Promise<void> {
      const now = Date.now();
      const windowStart = now - windowMs;
      let entry = store.get(identifier);
      if (!entry) { entry = { timestamps: [] }; store.set(identifier, entry); }
      entry.timestamps = entry.timestamps.filter(t => t > windowStart);
      if (entry.timestamps.length >= maxAttempts) {
        const oldestInWindow = entry.timestamps[0]!;
        const retryAfterMs = oldestInWindow + windowMs - now;
        if (onRateLimit) await onRateLimit(identifier);
        throw new RateLimitError(identifier, retryAfterMs);
      }
      entry.timestamps.push(now);
    },
    reset(identifier: string): void { store.delete(identifier); },
    remaining(identifier: string): number {
      const now = Date.now();
      const windowStart = now - windowMs;
      const entry = store.get(identifier);
      if (!entry) return maxAttempts;
      const recent = entry.timestamps.filter(t => t > windowStart).length;
      return Math.max(0, maxAttempts - recent);
    },
    cleanup,
    destroy(): void {
      if (cleanupTimer) { clearInterval(cleanupTimer); cleanupTimer = undefined; }
      store.clear();
    },
  };
}

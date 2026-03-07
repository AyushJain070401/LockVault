import { AuthErrorCode } from '../types/index.js';
import { LockVaultError } from '../utils/errors.js';

export class RateLimitError extends LockVaultError {
  public readonly retryAfterMs: number;

  constructor(identifier: string, retryAfterMs: number) {
    super(
      `Rate limit exceeded for "${identifier}". Retry after ${Math.ceil(retryAfterMs / 1000)}s.`,
      AuthErrorCode.RATE_LIMITED,
      429,
      { identifier, retryAfterMs },
    );
    this.name = 'RateLimitError';
    this.retryAfterMs = retryAfterMs;
    Object.setPrototypeOf(this, RateLimitError.prototype);
  }
}

interface RateLimitEntry {
  timestamps: number[];
}

export interface RateLimiterConfig {
  /** Time window in milliseconds (default: 60_000 = 1 minute) */
  windowMs: number;
  /** Maximum number of attempts allowed within the window (default: 5) */
  maxAttempts: number;
  /** Optional callback when rate limit is hit */
  onRateLimit?: (identifier: string) => void | Promise<void>;
}

/**
 * Sliding-window in-memory rate limiter.
 *
 * Tracks attempts per identifier (e.g., userId, IP address) and throws
 * `RateLimitError` when the limit is exceeded. Automatically cleans up
 * stale entries to prevent memory leaks.
 */
export class RateLimiter {
  private readonly config: Required<Omit<RateLimiterConfig, 'onRateLimit'>> & { onRateLimit?: RateLimiterConfig['onRateLimit'] };
  private readonly store = new Map<string, RateLimitEntry>();
  private cleanupTimer?: ReturnType<typeof setInterval>;

  constructor(config: Partial<RateLimiterConfig> = {}) {
    this.config = {
      windowMs: config.windowMs ?? 60_000,
      maxAttempts: config.maxAttempts ?? 5,
      onRateLimit: config.onRateLimit,
    };

    // Periodic cleanup every 5 minutes to prevent memory leaks
    this.cleanupTimer = setInterval(() => this.cleanup(), 300_000);
    if (this.cleanupTimer.unref) {
      this.cleanupTimer.unref();
    }
  }

  /**
   * Check and consume one attempt for the given identifier.
   * Throws `RateLimitError` if the limit is exceeded.
   */
  async consume(identifier: string): Promise<void> {
    const now = Date.now();
    const windowStart = now - this.config.windowMs;

    let entry = this.store.get(identifier);
    if (!entry) {
      entry = { timestamps: [] };
      this.store.set(identifier, entry);
    }

    // Remove timestamps outside the current window
    entry.timestamps = entry.timestamps.filter(t => t > windowStart);

    if (entry.timestamps.length >= this.config.maxAttempts) {
      const oldestInWindow = entry.timestamps[0]!;
      const retryAfterMs = oldestInWindow + this.config.windowMs - now;

      if (this.config.onRateLimit) {
        await this.config.onRateLimit(identifier);
      }

      throw new RateLimitError(identifier, retryAfterMs);
    }

    entry.timestamps.push(now);
  }

  /**
   * Reset the rate limit counter for a given identifier (e.g., after successful auth).
   */
  reset(identifier: string): void {
    this.store.delete(identifier);
  }

  /**
   * Get remaining attempts for an identifier.
   */
  remaining(identifier: string): number {
    const now = Date.now();
    const windowStart = now - this.config.windowMs;
    const entry = this.store.get(identifier);
    if (!entry) return this.config.maxAttempts;

    const recentAttempts = entry.timestamps.filter(t => t > windowStart).length;
    return Math.max(0, this.config.maxAttempts - recentAttempts);
  }

  /**
   * Clean up expired entries to prevent memory leaks.
   */
  cleanup(): void {
    const now = Date.now();
    const windowStart = now - this.config.windowMs;
    for (const [key, entry] of this.store) {
      entry.timestamps = entry.timestamps.filter(t => t > windowStart);
      if (entry.timestamps.length === 0) {
        this.store.delete(key);
      }
    }
  }

  /**
   * Stop the cleanup timer and clear internal state.
   */
  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = undefined;
    }
    this.store.clear();
  }
}

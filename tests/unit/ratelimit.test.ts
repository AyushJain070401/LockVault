import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { RateLimiter, RateLimitError } from '../../src/ratelimit/index.js';

describe('RateLimiter', () => {
  let limiter: RateLimiter;

  afterEach(() => {
    limiter?.destroy();
  });

  it('should allow requests under the limit', async () => {
    limiter = new RateLimiter({ windowMs: 60_000, maxAttempts: 3 });

    await limiter.consume('user-1');
    await limiter.consume('user-1');
    await limiter.consume('user-1');

    // Third attempt should be fine, fourth should fail
    await expect(limiter.consume('user-1')).rejects.toThrow(RateLimitError);
  });

  it('should track different identifiers independently', async () => {
    limiter = new RateLimiter({ windowMs: 60_000, maxAttempts: 1 });

    await limiter.consume('user-1');
    await limiter.consume('user-2'); // Different user should be fine

    await expect(limiter.consume('user-1')).rejects.toThrow(RateLimitError);
  });

  it('should report correct remaining attempts', async () => {
    limiter = new RateLimiter({ windowMs: 60_000, maxAttempts: 5 });

    expect(limiter.remaining('user-1')).toBe(5);
    await limiter.consume('user-1');
    expect(limiter.remaining('user-1')).toBe(4);
    await limiter.consume('user-1');
    expect(limiter.remaining('user-1')).toBe(3);
  });

  it('should reset an identifier', async () => {
    limiter = new RateLimiter({ windowMs: 60_000, maxAttempts: 1 });

    await limiter.consume('user-1');
    await expect(limiter.consume('user-1')).rejects.toThrow(RateLimitError);

    limiter.reset('user-1');
    await limiter.consume('user-1'); // Should work again
  });

  it('should include retryAfterMs in error', async () => {
    limiter = new RateLimiter({ windowMs: 60_000, maxAttempts: 1 });

    await limiter.consume('user-1');
    try {
      await limiter.consume('user-1');
      expect.unreachable('Should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(RateLimitError);
      expect((err as RateLimitError).retryAfterMs).toBeGreaterThan(0);
      expect((err as RateLimitError).retryAfterMs).toBeLessThanOrEqual(60_000);
      expect((err as RateLimitError).statusCode).toBe(429);
    }
  });

  it('should call onRateLimit callback when triggered', async () => {
    const onRateLimit = vi.fn();
    limiter = new RateLimiter({ windowMs: 60_000, maxAttempts: 1, onRateLimit });

    await limiter.consume('user-1');
    await expect(limiter.consume('user-1')).rejects.toThrow(RateLimitError);

    expect(onRateLimit).toHaveBeenCalledWith('user-1');
  });

  it('should clean up expired entries', async () => {
    limiter = new RateLimiter({ windowMs: 1, maxAttempts: 1 });

    await limiter.consume('user-1');
    await expect(limiter.consume('user-1')).rejects.toThrow(RateLimitError);

    // Wait for the window to expire
    await new Promise(r => setTimeout(r, 10));

    limiter.cleanup();
    await limiter.consume('user-1'); // Should succeed after expiry
  });
});

import { DatabaseAdapter, Session, OAuthLink } from '../../types/index.js';

const SAFE_PREFIX = /^[a-zA-Z_][a-zA-Z0-9_:]*$/;

/**
 * Redis adapter using `ioredis`.
 *
 * Uses hash maps and sets for efficient storage. Session and token
 * expiration leverages Redis TTL for automatic cleanup.
 */
export function createRedisAdapter(redis: RedisClient, options: { prefix?: string } = {}): DatabaseAdapter {
  {
    const prefix = options.prefix ?? 'lockvault:';
    if (!SAFE_PREFIX.test(prefix)) {
      throw new Error(`Invalid prefix "${prefix}": must match /^[a-zA-Z_][a-zA-Z0-9_:]*$/`);
    }

  function key(...parts: string[]): string {
    return `${prefix}${parts.join(':')}`;
  }

  const result: DatabaseAdapter = {
  // ─── Lifecycle ─────────────────────────────────────────────────────────

  async initialize(): Promise<void> { /* no-op */ }

  async close(): Promise<void> {
    await redis.quit();
  }

  // ─── Sessions ───────────────────────────────────────────────────────────

  async createSession(session: Session): Promise<Session> {
    const key = key('session', session.id);
    const ttl = Math.ceil((session.expiresAt.getTime() - Date.now()) / 1000);
    await redis.set(key, JSON.stringify(session), 'EX', Math.max(ttl, 1));
    await redis.sadd(key('user_sessions', session.userId), session.id);
    return session;
  }

  async getSession(sessionId: string): Promise<Session | null> {
    const data = await redis.get(key('session', sessionId));
    if (!data) return null;
    return deserializeSession(data);
  }

  async getSessionsByUser(userId: string): Promise<Session[]> {
    const ids = await redis.smembers(key('user_sessions', userId));
    const sessions: Session[] = [];
    for (const id of ids) {
      const s = await result.getSession(id);
      if (s) sessions.push(s);
      else await redis.srem(key('user_sessions', userId), id); // cleanup
    }
    return sessions;
  }

  async updateSession(sessionId: string, updates: Partial<Session>): Promise<Session | null> {
    const existing = await result.getSession(sessionId);
    if (!existing) return null;
    const updated = { ...existing, ...updates };
    const ttl = Math.ceil((updated.expiresAt.getTime() - Date.now()) / 1000);
    await redis.set(
      key('session', sessionId),
      JSON.stringify(updated),
      'EX', Math.max(ttl, 1),
    );
    return updated;
  }

  async deleteSession(sessionId: string): Promise<boolean> {
    const session = await result.getSession(sessionId);
    if (!session) return false;
    await redis.del(key('session', sessionId));
    await redis.srem(key('user_sessions', session.userId), sessionId);
    return true;
  }

  async deleteSessionsByUser(userId: string): Promise<number> {
    const ids = await redis.smembers(key('user_sessions', userId));
    let count = 0;
    for (const id of ids) {
      await redis.del(key('session', id));
      count++;
    }
    await redis.del(key('user_sessions', userId));
    return count;
  }

  async deleteExpiredSessions(): Promise<number> {
    // Redis TTL handles expiration automatically
    return 0;
  }

  // ─── Refresh Token Families ─────────────────────────────────────────────

  async storeRefreshTokenFamily(family: string, userId: string, generation: number): Promise<void> {
    await redis.hmset(key('family', family), {
      userId, generation: String(generation), revoked: 'false',
    });
  }

  async getRefreshTokenFamily(family: string): Promise<{ userId: string; generation: number; revoked: boolean } | null> {
    const data = await redis.hgetall(key('family', family));
    if (!data || !data.userId) return null;
    return {
      userId: data.userId,
      generation: parseInt(data.generation, 10),
      revoked: data.revoked === 'true',
    };
  }

  async revokeRefreshTokenFamily(family: string): Promise<void> {
    await redis.hset(key('family', family), 'revoked', 'true');
  }

  async incrementRefreshTokenGeneration(family: string): Promise<number> {
    return redis.hincrby(key('family', family), 'generation', 1);
  }

  // ─── Revocation List ────────────────────────────────────────────────────

  async addToRevocationList(jti: string, expiresAt: Date): Promise<void> {
    const ttl = Math.ceil((expiresAt.getTime() - Date.now()) / 1000);
    await redis.set(key('revoked', jti), '1', 'EX', Math.max(ttl, 1));
  }

  async isRevoked(jti: string): Promise<boolean> {
    const result = await redis.exists(key('revoked', jti));
    return result === 1;
  }

  async cleanupRevocationList(): Promise<number> {
    // Redis TTL handles expiration automatically
    return 0;
  }

  // ─── TOTP ──────────────────────────────────────────────────────────────

  async storeTOTPSecret(userId: string, secret: string): Promise<void> {
    await redis.set(key('totp', userId), secret);
  }

  async getTOTPSecret(userId: string): Promise<string | null> {
    return redis.get(key('totp', userId));
  }

  async removeTOTPSecret(userId: string): Promise<void> {
    await redis.del(key('totp', userId));
    await redis.del(key('backup', userId));
  }

  async storeBackupCodes(userId: string, codes: string[]): Promise<void> {
    const key = key('backup', userId);
    await redis.del(key);
    if (codes.length > 0) {
      await redis.sadd(key, ...codes);
    }
  }

  async getBackupCodes(userId: string): Promise<string[]> {
    return redis.smembers(key('backup', userId));
  }

  async consumeBackupCode(userId: string, code: string): Promise<boolean> {
    const result = await redis.srem(key('backup', userId), code.toUpperCase());
    return result > 0;
  }

  // ─── OAuth ─────────────────────────────────────────────────────────────

  async linkOAuthAccount(userId: string, link: OAuthLink): Promise<void> {
    const key = key('oauth', userId, link.provider);
    await redis.set(key, JSON.stringify(link));
    await redis.set(
      key('oauth_lookup', link.provider, link.providerUserId),
      userId,
    );
    await redis.sadd(key('oauth_providers', userId), link.provider);
  }

  async getOAuthLinks(userId: string): Promise<OAuthLink[]> {
    const providers = await redis.smembers(key('oauth_providers', userId));
    const links: OAuthLink[] = [];
    for (const provider of providers) {
      const data = await redis.get(key('oauth', userId, provider));
      if (data) {
        const parsed = JSON.parse(data);
        links.push({ ...parsed, linkedAt: new Date(parsed.linkedAt) });
      }
    }
    return links;
  }

  async findUserByOAuth(provider: string, providerUserId: string): Promise<string | null> {
    return redis.get(key('oauth_lookup', provider, providerUserId));
  }

  async unlinkOAuthAccount(userId: string, provider: string): Promise<boolean> {
    const data = await redis.get(key('oauth', userId, provider));
    if (!data) return false;
    const link = JSON.parse(data) as OAuthLink;
    await redis.del(key('oauth', userId, provider));
    await redis.del(key('oauth_lookup', provider, link.providerUserId));
    await redis.srem(key('oauth_providers', userId), provider);
    return true;
  }

  };
  return result;

  // ─── Helpers ────────────────────────────────────────────────────────────

  function deserializeSession(data: string): Session {
    const parsed = JSON.parse(data);
    return {
      ...parsed,
      createdAt: new Date(parsed.createdAt),
      expiresAt: new Date(parsed.expiresAt),
      lastActiveAt: new Date(parsed.lastActiveAt),
    };
  }

// Minimal type interface for ioredis compatibility
interface RedisClient {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ...args: (string | number)[]): Promise<string | null>;
  del(...keys: string[]): Promise<number>;
  exists(...keys: string[]): Promise<number>;
  sadd(key: string, ...members: string[]): Promise<number>;
  srem(key: string, ...members: string[]): Promise<number>;
  smembers(key: string): Promise<string[]>;
  hset(key: string, field: string, value: string): Promise<number>;
  hmset(key: string, data: Record<string, string>): Promise<string>;
  hgetall(key: string): Promise<Record<string, string>>;
  hincrby(key: string, field: string, increment: number): Promise<number>;
  quit(): Promise<string>;
}

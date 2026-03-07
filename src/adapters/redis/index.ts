import { DatabaseAdapter, Session, OAuthLink } from '../../types/index.js';

const SAFE_PREFIX = /^[a-zA-Z_][a-zA-Z0-9_:]*$/;

/**
 * Redis adapter using `ioredis`.
 *
 * Uses hash maps and sets for efficient storage. Session and token
 * expiration leverages Redis TTL for automatic cleanup.
 */
export class RedisAdapter implements DatabaseAdapter {
  private redis: RedisClient;
  private prefix: string;

  constructor(redis: RedisClient, options: { prefix?: string } = {}) {
    const prefix = options.prefix ?? 'lockvault:';
    if (!SAFE_PREFIX.test(prefix)) {
      throw new Error(`Invalid prefix "${prefix}": must match /^[a-zA-Z_][a-zA-Z0-9_:]*$/`);
    }
    this.redis = redis;
    this.prefix = prefix;
  }

  private key(...parts: string[]): string {
    return `${this.prefix}${parts.join(':')}`;
  }

  // ─── Lifecycle ─────────────────────────────────────────────────────────

  async initialize(): Promise<void> { /* no-op */ }

  async close(): Promise<void> {
    await this.redis.quit();
  }

  // ─── Sessions ───────────────────────────────────────────────────────────

  async createSession(session: Session): Promise<Session> {
    const key = this.key('session', session.id);
    const ttl = Math.ceil((session.expiresAt.getTime() - Date.now()) / 1000);
    await this.redis.set(key, JSON.stringify(session), 'EX', Math.max(ttl, 1));
    await this.redis.sadd(this.key('user_sessions', session.userId), session.id);
    return session;
  }

  async getSession(sessionId: string): Promise<Session | null> {
    const data = await this.redis.get(this.key('session', sessionId));
    if (!data) return null;
    return this.deserializeSession(data);
  }

  async getSessionsByUser(userId: string): Promise<Session[]> {
    const ids = await this.redis.smembers(this.key('user_sessions', userId));
    const sessions: Session[] = [];
    for (const id of ids) {
      const s = await this.getSession(id);
      if (s) sessions.push(s);
      else await this.redis.srem(this.key('user_sessions', userId), id); // cleanup
    }
    return sessions;
  }

  async updateSession(sessionId: string, updates: Partial<Session>): Promise<Session | null> {
    const existing = await this.getSession(sessionId);
    if (!existing) return null;
    const updated = { ...existing, ...updates };
    const ttl = Math.ceil((updated.expiresAt.getTime() - Date.now()) / 1000);
    await this.redis.set(
      this.key('session', sessionId),
      JSON.stringify(updated),
      'EX', Math.max(ttl, 1),
    );
    return updated;
  }

  async deleteSession(sessionId: string): Promise<boolean> {
    const session = await this.getSession(sessionId);
    if (!session) return false;
    await this.redis.del(this.key('session', sessionId));
    await this.redis.srem(this.key('user_sessions', session.userId), sessionId);
    return true;
  }

  async deleteSessionsByUser(userId: string): Promise<number> {
    const ids = await this.redis.smembers(this.key('user_sessions', userId));
    let count = 0;
    for (const id of ids) {
      await this.redis.del(this.key('session', id));
      count++;
    }
    await this.redis.del(this.key('user_sessions', userId));
    return count;
  }

  async deleteExpiredSessions(): Promise<number> {
    // Redis TTL handles expiration automatically
    return 0;
  }

  // ─── Refresh Token Families ─────────────────────────────────────────────

  async storeRefreshTokenFamily(family: string, userId: string, generation: number): Promise<void> {
    await this.redis.hmset(this.key('family', family), {
      userId, generation: String(generation), revoked: 'false',
    });
  }

  async getRefreshTokenFamily(family: string): Promise<{ userId: string; generation: number; revoked: boolean } | null> {
    const data = await this.redis.hgetall(this.key('family', family));
    if (!data || !data.userId) return null;
    return {
      userId: data.userId,
      generation: parseInt(data.generation, 10),
      revoked: data.revoked === 'true',
    };
  }

  async revokeRefreshTokenFamily(family: string): Promise<void> {
    await this.redis.hset(this.key('family', family), 'revoked', 'true');
  }

  async incrementRefreshTokenGeneration(family: string): Promise<number> {
    return this.redis.hincrby(this.key('family', family), 'generation', 1);
  }

  // ─── Revocation List ────────────────────────────────────────────────────

  async addToRevocationList(jti: string, expiresAt: Date): Promise<void> {
    const ttl = Math.ceil((expiresAt.getTime() - Date.now()) / 1000);
    await this.redis.set(this.key('revoked', jti), '1', 'EX', Math.max(ttl, 1));
  }

  async isRevoked(jti: string): Promise<boolean> {
    const result = await this.redis.exists(this.key('revoked', jti));
    return result === 1;
  }

  async cleanupRevocationList(): Promise<number> {
    // Redis TTL handles expiration automatically
    return 0;
  }

  // ─── TOTP ──────────────────────────────────────────────────────────────

  async storeTOTPSecret(userId: string, secret: string): Promise<void> {
    await this.redis.set(this.key('totp', userId), secret);
  }

  async getTOTPSecret(userId: string): Promise<string | null> {
    return this.redis.get(this.key('totp', userId));
  }

  async removeTOTPSecret(userId: string): Promise<void> {
    await this.redis.del(this.key('totp', userId));
    await this.redis.del(this.key('backup', userId));
  }

  async storeBackupCodes(userId: string, codes: string[]): Promise<void> {
    const key = this.key('backup', userId);
    await this.redis.del(key);
    if (codes.length > 0) {
      await this.redis.sadd(key, ...codes);
    }
  }

  async getBackupCodes(userId: string): Promise<string[]> {
    return this.redis.smembers(this.key('backup', userId));
  }

  async consumeBackupCode(userId: string, code: string): Promise<boolean> {
    const result = await this.redis.srem(this.key('backup', userId), code.toUpperCase());
    return result > 0;
  }

  // ─── OAuth ─────────────────────────────────────────────────────────────

  async linkOAuthAccount(userId: string, link: OAuthLink): Promise<void> {
    const key = this.key('oauth', userId, link.provider);
    await this.redis.set(key, JSON.stringify(link));
    await this.redis.set(
      this.key('oauth_lookup', link.provider, link.providerUserId),
      userId,
    );
    await this.redis.sadd(this.key('oauth_providers', userId), link.provider);
  }

  async getOAuthLinks(userId: string): Promise<OAuthLink[]> {
    const providers = await this.redis.smembers(this.key('oauth_providers', userId));
    const links: OAuthLink[] = [];
    for (const provider of providers) {
      const data = await this.redis.get(this.key('oauth', userId, provider));
      if (data) {
        const parsed = JSON.parse(data);
        links.push({ ...parsed, linkedAt: new Date(parsed.linkedAt) });
      }
    }
    return links;
  }

  async findUserByOAuth(provider: string, providerUserId: string): Promise<string | null> {
    return this.redis.get(this.key('oauth_lookup', provider, providerUserId));
  }

  async unlinkOAuthAccount(userId: string, provider: string): Promise<boolean> {
    const data = await this.redis.get(this.key('oauth', userId, provider));
    if (!data) return false;
    const link = JSON.parse(data) as OAuthLink;
    await this.redis.del(this.key('oauth', userId, provider));
    await this.redis.del(this.key('oauth_lookup', provider, link.providerUserId));
    await this.redis.srem(this.key('oauth_providers', userId), provider);
    return true;
  }

  // ─── Helpers ────────────────────────────────────────────────────────────

  private deserializeSession(data: string): Session {
    const parsed = JSON.parse(data);
    return {
      ...parsed,
      createdAt: new Date(parsed.createdAt),
      expiresAt: new Date(parsed.expiresAt),
      lastActiveAt: new Date(parsed.lastActiveAt),
    };
  }
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

import { DatabaseAdapter, Session, OAuthLink } from '../../types/index.js';

const SAFE_PREFIX = /^[a-zA-Z_][a-zA-Z0-9_:]*$/;

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

function deserializeSession(data: string): Session {
  const parsed = JSON.parse(data);
  return {
    ...parsed,
    createdAt: new Date(parsed.createdAt),
    expiresAt: new Date(parsed.expiresAt),
    lastActiveAt: new Date(parsed.lastActiveAt),
  };
}

/**
 * Redis adapter using `ioredis`.
 *
 * Uses hash maps and sets for efficient storage. Session and token
 * expiration leverages Redis TTL for automatic cleanup.
 */
export function createRedisAdapter(redis: RedisClient, options: { prefix?: string } = {}): DatabaseAdapter {
  const pfx = options.prefix ?? 'lockvault:';
  if (!SAFE_PREFIX.test(pfx)) {
    throw new Error(`Invalid prefix "${pfx}": must match /^[a-zA-Z_][a-zA-Z0-9_:]*$/`);
  }

  function k(...parts: string[]): string {
    return `${pfx}${parts.join(':')}`;
  }

  const adapter: DatabaseAdapter = {
    async initialize() { /* no-op */ },

    async close() {
      await redis.quit();
    },

    // ─── Sessions ───────────────────────────────────────────────────────────

    async createSession(session) {
      const sessionKey = k('session', session.id);
      const ttl = Math.ceil((session.expiresAt.getTime() - Date.now()) / 1000);
      await redis.set(sessionKey, JSON.stringify(session), 'EX', Math.max(ttl, 1));
      await redis.sadd(k('user_sessions', session.userId), session.id);
      return session;
    },

    async getSession(sessionId) {
      const data = await redis.get(k('session', sessionId));
      if (!data) return null;
      return deserializeSession(data);
    },

    async getSessionsByUser(userId) {
      const ids = await redis.smembers(k('user_sessions', userId));
      const sessions: Session[] = [];
      for (const id of ids) {
        const s = await adapter.getSession(id);
        if (s) sessions.push(s);
        else await redis.srem(k('user_sessions', userId), id); // cleanup stale refs
      }
      return sessions;
    },

    async updateSession(sessionId, updates) {
      const existing = await adapter.getSession(sessionId);
      if (!existing) return null;
      const updated = { ...existing, ...updates };
      const ttl = Math.ceil((updated.expiresAt.getTime() - Date.now()) / 1000);
      await redis.set(k('session', sessionId), JSON.stringify(updated), 'EX', Math.max(ttl, 1));
      return updated;
    },

    async deleteSession(sessionId) {
      const session = await adapter.getSession(sessionId);
      if (!session) return false;
      await redis.del(k('session', sessionId));
      await redis.srem(k('user_sessions', session.userId), sessionId);
      return true;
    },

    async deleteSessionsByUser(userId) {
      const ids = await redis.smembers(k('user_sessions', userId));
      let count = 0;
      for (const id of ids) {
        await redis.del(k('session', id));
        count++;
      }
      await redis.del(k('user_sessions', userId));
      return count;
    },

    async deleteExpiredSessions() {
      // Redis TTL handles expiration automatically
      return 0;
    },

    // ─── Refresh Token Families ─────────────────────────────────────────────

    async storeRefreshTokenFamily(family, userId, generation) {
      await redis.hmset(k('family', family), {
        userId, generation: String(generation), revoked: 'false',
      });
    },

    async getRefreshTokenFamily(family) {
      const data = await redis.hgetall(k('family', family));
      if (!data || !data.userId) return null;
      return {
        userId: data.userId,
        generation: parseInt(data.generation, 10),
        revoked: data.revoked === 'true',
      };
    },

    async revokeRefreshTokenFamily(family) {
      await redis.hset(k('family', family), 'revoked', 'true');
    },

    async incrementRefreshTokenGeneration(family) {
      return redis.hincrby(k('family', family), 'generation', 1);
    },

    // ─── Revocation List ────────────────────────────────────────────────────

    async addToRevocationList(jti, expiresAt) {
      const ttl = Math.ceil((expiresAt.getTime() - Date.now()) / 1000);
      await redis.set(k('revoked', jti), '1', 'EX', Math.max(ttl, 1));
    },

    async isRevoked(jti) {
      const exists = await redis.exists(k('revoked', jti));
      return exists === 1;
    },

    async cleanupRevocationList() {
      // Redis TTL handles expiration automatically
      return 0;
    },

    // ─── TOTP ──────────────────────────────────────────────────────────────

    async storeTOTPSecret(userId, secret) {
      await redis.set(k('totp', userId), secret);
    },

    async getTOTPSecret(userId) {
      return redis.get(k('totp', userId));
    },

    async removeTOTPSecret(userId) {
      await redis.del(k('totp', userId));
      await redis.del(k('backup', userId));
    },

    async storeBackupCodes(userId, codes) {
      const backupKey = k('backup', userId);
      await redis.del(backupKey);
      if (codes.length > 0) {
        await redis.sadd(backupKey, ...codes);
      }
    },

    async getBackupCodes(userId) {
      return redis.smembers(k('backup', userId));
    },

    async consumeBackupCode(userId, code) {
      const removed = await redis.srem(k('backup', userId), code.toUpperCase());
      return removed > 0;
    },

    // ─── OAuth ─────────────────────────────────────────────────────────────

    async linkOAuthAccount(userId, link) {
      const oauthKey = k('oauth', userId, link.provider);
      await redis.set(oauthKey, JSON.stringify(link));
      await redis.set(k('oauth_lookup', link.provider, link.providerUserId), userId);
      await redis.sadd(k('oauth_providers', userId), link.provider);
    },

    async getOAuthLinks(userId) {
      const providers = await redis.smembers(k('oauth_providers', userId));
      const links: OAuthLink[] = [];
      for (const provider of providers) {
        const data = await redis.get(k('oauth', userId, provider));
        if (data) {
          const parsed = JSON.parse(data);
          links.push({ ...parsed, linkedAt: new Date(parsed.linkedAt) });
        }
      }
      return links;
    },

    async findUserByOAuth(provider, providerUserId) {
      return redis.get(k('oauth_lookup', provider, providerUserId));
    },

    async unlinkOAuthAccount(userId, provider) {
      const data = await redis.get(k('oauth', userId, provider));
      if (!data) return false;
      const link = JSON.parse(data) as OAuthLink;
      await redis.del(k('oauth', userId, provider));
      await redis.del(k('oauth_lookup', provider, link.providerUserId));
      await redis.srem(k('oauth_providers', userId), provider);
      return true;
    },
  };

  return adapter;
}

// src/adapters/redis/index.ts
var SAFE_PREFIX = /^[a-zA-Z_][a-zA-Z0-9_:]*$/;
var RedisAdapter = class {
  redis;
  prefix;
  constructor(redis, options = {}) {
    const prefix = options.prefix ?? "lockvault:";
    if (!SAFE_PREFIX.test(prefix)) {
      throw new Error(`Invalid prefix "${prefix}": must match /^[a-zA-Z_][a-zA-Z0-9_:]*$/`);
    }
    this.redis = redis;
    this.prefix = prefix;
  }
  key(...parts) {
    return `${this.prefix}${parts.join(":")}`;
  }
  // ─── Lifecycle ─────────────────────────────────────────────────────────
  async initialize() {
  }
  async close() {
    await this.redis.quit();
  }
  // ─── Sessions ───────────────────────────────────────────────────────────
  async createSession(session) {
    const key = this.key("session", session.id);
    const ttl = Math.ceil((session.expiresAt.getTime() - Date.now()) / 1e3);
    await this.redis.set(key, JSON.stringify(session), "EX", Math.max(ttl, 1));
    await this.redis.sadd(this.key("user_sessions", session.userId), session.id);
    return session;
  }
  async getSession(sessionId) {
    const data = await this.redis.get(this.key("session", sessionId));
    if (!data) return null;
    return this.deserializeSession(data);
  }
  async getSessionsByUser(userId) {
    const ids = await this.redis.smembers(this.key("user_sessions", userId));
    const sessions = [];
    for (const id of ids) {
      const s = await this.getSession(id);
      if (s) sessions.push(s);
      else await this.redis.srem(this.key("user_sessions", userId), id);
    }
    return sessions;
  }
  async updateSession(sessionId, updates) {
    const existing = await this.getSession(sessionId);
    if (!existing) return null;
    const updated = { ...existing, ...updates };
    const ttl = Math.ceil((updated.expiresAt.getTime() - Date.now()) / 1e3);
    await this.redis.set(
      this.key("session", sessionId),
      JSON.stringify(updated),
      "EX",
      Math.max(ttl, 1)
    );
    return updated;
  }
  async deleteSession(sessionId) {
    const session = await this.getSession(sessionId);
    if (!session) return false;
    await this.redis.del(this.key("session", sessionId));
    await this.redis.srem(this.key("user_sessions", session.userId), sessionId);
    return true;
  }
  async deleteSessionsByUser(userId) {
    const ids = await this.redis.smembers(this.key("user_sessions", userId));
    let count = 0;
    for (const id of ids) {
      await this.redis.del(this.key("session", id));
      count++;
    }
    await this.redis.del(this.key("user_sessions", userId));
    return count;
  }
  async deleteExpiredSessions() {
    return 0;
  }
  // ─── Refresh Token Families ─────────────────────────────────────────────
  async storeRefreshTokenFamily(family, userId, generation) {
    await this.redis.hmset(this.key("family", family), {
      userId,
      generation: String(generation),
      revoked: "false"
    });
  }
  async getRefreshTokenFamily(family) {
    const data = await this.redis.hgetall(this.key("family", family));
    if (!data || !data.userId) return null;
    return {
      userId: data.userId,
      generation: parseInt(data.generation, 10),
      revoked: data.revoked === "true"
    };
  }
  async revokeRefreshTokenFamily(family) {
    await this.redis.hset(this.key("family", family), "revoked", "true");
  }
  async incrementRefreshTokenGeneration(family) {
    return this.redis.hincrby(this.key("family", family), "generation", 1);
  }
  // ─── Revocation List ────────────────────────────────────────────────────
  async addToRevocationList(jti, expiresAt) {
    const ttl = Math.ceil((expiresAt.getTime() - Date.now()) / 1e3);
    await this.redis.set(this.key("revoked", jti), "1", "EX", Math.max(ttl, 1));
  }
  async isRevoked(jti) {
    const result = await this.redis.exists(this.key("revoked", jti));
    return result === 1;
  }
  async cleanupRevocationList() {
    return 0;
  }
  // ─── TOTP ──────────────────────────────────────────────────────────────
  async storeTOTPSecret(userId, secret) {
    await this.redis.set(this.key("totp", userId), secret);
  }
  async getTOTPSecret(userId) {
    return this.redis.get(this.key("totp", userId));
  }
  async removeTOTPSecret(userId) {
    await this.redis.del(this.key("totp", userId));
    await this.redis.del(this.key("backup", userId));
  }
  async storeBackupCodes(userId, codes) {
    const key = this.key("backup", userId);
    await this.redis.del(key);
    if (codes.length > 0) {
      await this.redis.sadd(key, ...codes);
    }
  }
  async getBackupCodes(userId) {
    return this.redis.smembers(this.key("backup", userId));
  }
  async consumeBackupCode(userId, code) {
    const result = await this.redis.srem(this.key("backup", userId), code.toUpperCase());
    return result > 0;
  }
  // ─── OAuth ─────────────────────────────────────────────────────────────
  async linkOAuthAccount(userId, link) {
    const key = this.key("oauth", userId, link.provider);
    await this.redis.set(key, JSON.stringify(link));
    await this.redis.set(
      this.key("oauth_lookup", link.provider, link.providerUserId),
      userId
    );
    await this.redis.sadd(this.key("oauth_providers", userId), link.provider);
  }
  async getOAuthLinks(userId) {
    const providers = await this.redis.smembers(this.key("oauth_providers", userId));
    const links = [];
    for (const provider of providers) {
      const data = await this.redis.get(this.key("oauth", userId, provider));
      if (data) {
        const parsed = JSON.parse(data);
        links.push({ ...parsed, linkedAt: new Date(parsed.linkedAt) });
      }
    }
    return links;
  }
  async findUserByOAuth(provider, providerUserId) {
    return this.redis.get(this.key("oauth_lookup", provider, providerUserId));
  }
  async unlinkOAuthAccount(userId, provider) {
    const data = await this.redis.get(this.key("oauth", userId, provider));
    if (!data) return false;
    const link = JSON.parse(data);
    await this.redis.del(this.key("oauth", userId, provider));
    await this.redis.del(this.key("oauth_lookup", provider, link.providerUserId));
    await this.redis.srem(this.key("oauth_providers", userId), provider);
    return true;
  }
  // ─── Helpers ────────────────────────────────────────────────────────────
  deserializeSession(data) {
    const parsed = JSON.parse(data);
    return {
      ...parsed,
      createdAt: new Date(parsed.createdAt),
      expiresAt: new Date(parsed.expiresAt),
      lastActiveAt: new Date(parsed.lastActiveAt)
    };
  }
};

export { RedisAdapter };
//# sourceMappingURL=index.mjs.map
//# sourceMappingURL=index.mjs.map
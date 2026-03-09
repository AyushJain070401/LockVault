// src/adapters/mongodb/index.ts
var SAFE_PREFIX = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
function mapDoc(doc) {
  const { _id, ...rest } = doc;
  return { id: _id, ...rest };
}
function createMongoDBAdapter(db, options = {}) {
  const prefix = options.collectionPrefix ?? "lockvault_";
  if (!SAFE_PREFIX.test(prefix)) {
    throw new Error(`Invalid collectionPrefix "${prefix}": must match /^[a-zA-Z_][a-zA-Z0-9_]*$/`);
  }
  function col(name) {
    return db.collection(`${prefix}${name}`);
  }
  return {
    async initialize() {
      await col("sessions").createIndex({ userId: 1 });
      await col("sessions").createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
      await col("revocation_list").createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
      await col("oauth_links").createIndex({ provider: 1, providerUserId: 1 });
    },
    async close() {
    },
    // ─── Sessions ───────────────────────────────────────────────────────────
    async createSession(session) {
      await col("sessions").insertOne({ _id: session.id, ...session });
      return session;
    },
    async getSession(sessionId) {
      const doc = await col("sessions").findOne({ _id: sessionId });
      return doc ? mapDoc(doc) : null;
    },
    async getSessionsByUser(userId) {
      const docs = await col("sessions").find({ userId }).sort({ createdAt: -1 }).toArray();
      return docs.map((d) => mapDoc(d));
    },
    async updateSession(sessionId, updates) {
      const result = await col("sessions").findOneAndUpdate(
        { _id: sessionId },
        { $set: updates },
        { returnDocument: "after" }
      );
      return result ? mapDoc(result) : null;
    },
    async deleteSession(sessionId) {
      const result = await col("sessions").deleteOne({ _id: sessionId });
      return result.deletedCount > 0;
    },
    async deleteSessionsByUser(userId) {
      const result = await col("sessions").deleteMany({ userId });
      return result.deletedCount;
    },
    async deleteExpiredSessions() {
      const result = await col("sessions").deleteMany({
        $or: [{ expiresAt: { $lt: /* @__PURE__ */ new Date() } }, { isRevoked: true }]
      });
      return result.deletedCount;
    },
    // ─── Refresh Token Families ─────────────────────────────────────────────
    async storeRefreshTokenFamily(family, userId, generation) {
      await col("refresh_families").updateOne(
        { _id: family },
        { $set: { userId, generation, revoked: false } },
        { upsert: true }
      );
    },
    async getRefreshTokenFamily(family) {
      const doc = await col("refresh_families").findOne({ _id: family });
      if (!doc) return null;
      return { userId: doc.userId, generation: doc.generation, revoked: doc.revoked };
    },
    async revokeRefreshTokenFamily(family) {
      await col("refresh_families").updateOne(
        { _id: family },
        { $set: { revoked: true } }
      );
    },
    async incrementRefreshTokenGeneration(family) {
      const result = await col("refresh_families").findOneAndUpdate(
        { _id: family },
        { $inc: { generation: 1 } },
        { returnDocument: "after" }
      );
      return result?.generation ?? 0;
    },
    // ─── Revocation List ────────────────────────────────────────────────────
    async addToRevocationList(jti, expiresAt) {
      await col("revocation_list").updateOne(
        { _id: jti },
        { $set: { expiresAt } },
        { upsert: true }
      );
    },
    async isRevoked(jti) {
      const doc = await col("revocation_list").findOne({ _id: jti });
      return doc !== null;
    },
    async cleanupRevocationList() {
      const result = await col("revocation_list").deleteMany({ expiresAt: { $lt: /* @__PURE__ */ new Date() } });
      return result.deletedCount;
    },
    // ─── TOTP ──────────────────────────────────────────────────────────────
    async storeTOTPSecret(userId, secret) {
      await col("totp_secrets").updateOne({ _id: userId }, { $set: { secret } }, { upsert: true });
    },
    async getTOTPSecret(userId) {
      const doc = await col("totp_secrets").findOne({ _id: userId });
      return doc?.secret ?? null;
    },
    async removeTOTPSecret(userId) {
      await col("totp_secrets").deleteOne({ _id: userId });
      await col("backup_codes").deleteMany({ userId });
    },
    async storeBackupCodes(userId, codes) {
      await col("backup_codes").deleteMany({ userId });
      if (codes.length > 0) {
        await col("backup_codes").insertMany(codes.map((code) => ({ userId, code })));
      }
    },
    async getBackupCodes(userId) {
      const docs = await col("backup_codes").find({ userId }).toArray();
      return docs.map((d) => d.code);
    },
    async consumeBackupCode(userId, code) {
      const result = await col("backup_codes").deleteOne({ userId, code: code.toUpperCase() });
      return result.deletedCount > 0;
    },
    // ─── OAuth ─────────────────────────────────────────────────────────────
    async linkOAuthAccount(userId, link) {
      await col("oauth_links").updateOne(
        { userId, provider: link.provider },
        { $set: { ...link, userId } },
        { upsert: true }
      );
    },
    async getOAuthLinks(userId) {
      const docs = await col("oauth_links").find({ userId }).toArray();
      return docs.map((d) => ({
        provider: d.provider,
        providerUserId: d.providerUserId,
        accessToken: d.accessToken,
        refreshToken: d.refreshToken,
        profile: d.profile,
        linkedAt: new Date(d.linkedAt)
      }));
    },
    async findUserByOAuth(provider, providerUserId) {
      const doc = await col("oauth_links").findOne({ provider, providerUserId });
      return doc?.userId ?? null;
    },
    async unlinkOAuthAccount(userId, provider) {
      const result = await col("oauth_links").deleteOne({ userId, provider });
      return result.deletedCount > 0;
    }
  };
}

export { createMongoDBAdapter };
//# sourceMappingURL=index.mjs.map
//# sourceMappingURL=index.mjs.map
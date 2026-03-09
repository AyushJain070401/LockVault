import { DatabaseAdapter, Session, OAuthLink } from '../../types/index.js';

const SAFE_PREFIX = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

/**
 * MongoDB adapter using the official `mongodb` driver.
 *
 * Expects a `mongodb.Db` instance. Call `initialize()` to create indexes.
 */
export function createMongoDBAdapter(db: MongoDb, options: { collectionPrefix?: string } = {}): DatabaseAdapter {
  {
    const prefix = options.collectionPrefix ?? 'lockvault_';
    if (!SAFE_PREFIX.test(prefix)) {
      throw new Error(`Invalid collectionPrefix "${prefix}": must match /^[a-zA-Z_][a-zA-Z0-9_]*$/`);
    }

  function col(name: string) {
    return db.collection(`${collectionPrefix}${name}`);
  }

  return {
  // ─── Lifecycle ─────────────────────────────────────────────────────────

  async initialize(): Promise<void> {
    await col('sessions').createIndex({ userId: 1 });
    await col('sessions').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
    await col('revocation_list').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
    await col('oauth_links').createIndex({ provider: 1, providerUserId: 1 });
  }

  async close(): Promise<void> { /* managed externally */ }

  // ─── Sessions ───────────────────────────────────────────────────────────

  async createSession(session: Session): Promise<Session> {
    await col('sessions').insertOne({ _id: session.id as unknown, ...session });
    return session;
  }

  async getSession(sessionId: string): Promise<Session | null> {
    const doc = await col('sessions').findOne({ _id: sessionId as unknown });
    return doc ? mapDoc<Session>(doc) : null;
  }

  async getSessionsByUser(userId: string): Promise<Session[]> {
    const docs = await col('sessions').find({ userId }).sort({ createdAt: -1 }).toArray();
    return docs.map(d => mapDoc<Session>(d));
  }

  async updateSession(sessionId: string, updates: Partial<Session>): Promise<Session | null> {
    const result = await col('sessions').findOneAndUpdate(
      { _id: sessionId as unknown },
      { $set: updates },
      { returnDocument: 'after' },
    );
    return result ? mapDoc<Session>(result) : null;
  }

  async deleteSession(sessionId: string): Promise<boolean> {
    const result = await col('sessions').deleteOne({ _id: sessionId as unknown });
    return result.deletedCount > 0;
  }

  async deleteSessionsByUser(userId: string): Promise<number> {
    const result = await col('sessions').deleteMany({ userId });
    return result.deletedCount;
  }

  async deleteExpiredSessions(): Promise<number> {
    const result = await col('sessions').deleteMany({
      $or: [{ expiresAt: { $lt: new Date() } }, { isRevoked: true }],
    });
    return result.deletedCount;
  }

  // ─── Refresh Token Families ─────────────────────────────────────────────

  async storeRefreshTokenFamily(family: string, userId: string, generation: number): Promise<void> {
    await col('refresh_families').updateOne(
      { _id: family as unknown },
      { $set: { userId, generation, revoked: false } },
      { upsert: true },
    );
  }

  async getRefreshTokenFamily(family: string): Promise<{ userId: string; generation: number; revoked: boolean } | null> {
    const doc = await col('refresh_families').findOne({ _id: family as unknown });
    if (!doc) return null;
    return { userId: doc.userId as string, generation: doc.generation as number, revoked: doc.revoked as boolean };
  }

  async revokeRefreshTokenFamily(family: string): Promise<void> {
    await col('refresh_families').updateOne(
      { _id: family as unknown },
      { $set: { revoked: true } },
    );
  }

  async incrementRefreshTokenGeneration(family: string): Promise<number> {
    const result = await col('refresh_families').findOneAndUpdate(
      { _id: family as unknown },
      { $inc: { generation: 1 } },
      { returnDocument: 'after' },
    );
    return (result?.generation as number) ?? 0;
  }

  // ─── Revocation List ────────────────────────────────────────────────────

  async addToRevocationList(jti: string, expiresAt: Date): Promise<void> {
    await col('revocation_list').updateOne(
      { _id: jti as unknown },
      { $set: { expiresAt } },
      { upsert: true },
    );
  }

  async isRevoked(jti: string): Promise<boolean> {
    const doc = await col('revocation_list').findOne({ _id: jti as unknown });
    return doc !== null;
  }

  async cleanupRevocationList(): Promise<number> {
    const result = await col('revocation_list').deleteMany({ expiresAt: { $lt: new Date() } });
    return result.deletedCount;
  }

  // ─── TOTP ──────────────────────────────────────────────────────────────

  async storeTOTPSecret(userId: string, secret: string): Promise<void> {
    await col('totp_secrets').updateOne(
      { _id: userId as unknown },
      { $set: { secret } },
      { upsert: true },
    );
  }

  async getTOTPSecret(userId: string): Promise<string | null> {
    const doc = await col('totp_secrets').findOne({ _id: userId as unknown });
    return (doc?.secret as string) ?? null;
  }

  async removeTOTPSecret(userId: string): Promise<void> {
    await col('totp_secrets').deleteOne({ _id: userId as unknown });
    await col('backup_codes').deleteMany({ userId });
  }

  async storeBackupCodes(userId: string, codes: string[]): Promise<void> {
    await col('backup_codes').deleteMany({ userId });
    if (codes.length > 0) {
      await col('backup_codes').insertMany(codes.map(code => ({ userId, code })));
    }
  }

  async getBackupCodes(userId: string): Promise<string[]> {
    const docs = await col('backup_codes').find({ userId }).toArray();
    return docs.map(d => d.code as string);
  }

  async consumeBackupCode(userId: string, code: string): Promise<boolean> {
    const result = await col('backup_codes').deleteOne({ userId, code: code.toUpperCase() });
    return result.deletedCount > 0;
  }

  // ─── OAuth ─────────────────────────────────────────────────────────────

  async linkOAuthAccount(userId: string, link: OAuthLink): Promise<void> {
    await col('oauth_links').updateOne(
      { userId, provider: link.provider },
      { $set: { ...link, userId } },
      { upsert: true },
    );
  }

  async getOAuthLinks(userId: string): Promise<OAuthLink[]> {
    const docs = await col('oauth_links').find({ userId }).toArray();
    return docs.map(d => ({
      provider: d.provider as string,
      providerUserId: d.providerUserId as string,
      accessToken: d.accessToken as string | undefined,
      refreshToken: d.refreshToken as string | undefined,
      profile: d.profile as Record<string, unknown> | undefined,
      linkedAt: new Date(d.linkedAt as string),
    }));
  }

  async findUserByOAuth(provider: string, providerUserId: string): Promise<string | null> {
    const doc = await col('oauth_links').findOne({ provider, providerUserId });
    return (doc?.userId as string) ?? null;
  }

  async unlinkOAuthAccount(userId: string, provider: string): Promise<boolean> {
    const result = await col('oauth_links').deleteOne({ userId, provider });
    return result.deletedCount > 0;
  }

  };

  // ─── Helpers ────────────────────────────────────────────────────────────

  function mapDoc<T>(doc: MongoDocument): T {
    const { _id, ...rest } = doc;
    return { id: _id, ...rest } as T;
  }

// Minimal types to avoid hard mongodb dependency
interface MongoDb {
  collection(name: string): MongoCollection;
}

interface MongoCollection {
  createIndex(keys: Record<string, unknown>, options?: Record<string, unknown>): Promise<string>;
  insertOne(doc: unknown): Promise<{ insertedId: unknown }>;
  insertMany(docs: unknown[]): Promise<{ insertedCount: number }>;
  findOne(filter: unknown): Promise<MongoDocument | null>;
  find(filter: unknown): MongoCursor;
  findOneAndUpdate(
    filter: unknown, update: unknown, options?: Record<string, unknown>,
  ): Promise<MongoDocument | null>;
  updateOne(
    filter: unknown, update: unknown, options?: Record<string, unknown>,
  ): Promise<{ modifiedCount: number; upsertedCount: number }>;
  deleteOne(filter: unknown): Promise<{ deletedCount: number }>;
  deleteMany(filter: unknown): Promise<{ deletedCount: number }>;
}

interface MongoCursor {
  sort(spec: Record<string, number>): MongoCursor;
  toArray(): Promise<MongoDocument[]>;
}

type MongoDocument = Record<string, unknown> & { _id: unknown };

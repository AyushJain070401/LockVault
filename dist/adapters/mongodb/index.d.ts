import { D as DatabaseAdapter, S as Session, e as OAuthLink } from '../../index-BPNrRCYx.js';

/**
 * MongoDB adapter using the official `mongodb` driver.
 *
 * Expects a `mongodb.Db` instance. Call `initialize()` to create indexes.
 */
declare class MongoDBAdapter implements DatabaseAdapter {
    private db;
    private collectionPrefix;
    constructor(db: MongoDb, options?: {
        collectionPrefix?: string;
    });
    private col;
    initialize(): Promise<void>;
    close(): Promise<void>;
    createSession(session: Session): Promise<Session>;
    getSession(sessionId: string): Promise<Session | null>;
    getSessionsByUser(userId: string): Promise<Session[]>;
    updateSession(sessionId: string, updates: Partial<Session>): Promise<Session | null>;
    deleteSession(sessionId: string): Promise<boolean>;
    deleteSessionsByUser(userId: string): Promise<number>;
    deleteExpiredSessions(): Promise<number>;
    storeRefreshTokenFamily(family: string, userId: string, generation: number): Promise<void>;
    getRefreshTokenFamily(family: string): Promise<{
        userId: string;
        generation: number;
        revoked: boolean;
    } | null>;
    revokeRefreshTokenFamily(family: string): Promise<void>;
    incrementRefreshTokenGeneration(family: string): Promise<number>;
    addToRevocationList(jti: string, expiresAt: Date): Promise<void>;
    isRevoked(jti: string): Promise<boolean>;
    cleanupRevocationList(): Promise<number>;
    storeTOTPSecret(userId: string, secret: string): Promise<void>;
    getTOTPSecret(userId: string): Promise<string | null>;
    removeTOTPSecret(userId: string): Promise<void>;
    storeBackupCodes(userId: string, codes: string[]): Promise<void>;
    getBackupCodes(userId: string): Promise<string[]>;
    consumeBackupCode(userId: string, code: string): Promise<boolean>;
    linkOAuthAccount(userId: string, link: OAuthLink): Promise<void>;
    getOAuthLinks(userId: string): Promise<OAuthLink[]>;
    findUserByOAuth(provider: string, providerUserId: string): Promise<string | null>;
    unlinkOAuthAccount(userId: string, provider: string): Promise<boolean>;
    private mapDoc;
}
interface MongoDb {
    collection(name: string): MongoCollection;
}
interface MongoCollection {
    createIndex(keys: Record<string, unknown>, options?: Record<string, unknown>): Promise<string>;
    insertOne(doc: unknown): Promise<{
        insertedId: unknown;
    }>;
    insertMany(docs: unknown[]): Promise<{
        insertedCount: number;
    }>;
    findOne(filter: unknown): Promise<MongoDocument | null>;
    find(filter: unknown): MongoCursor;
    findOneAndUpdate(filter: unknown, update: unknown, options?: Record<string, unknown>): Promise<MongoDocument | null>;
    updateOne(filter: unknown, update: unknown, options?: Record<string, unknown>): Promise<{
        modifiedCount: number;
        upsertedCount: number;
    }>;
    deleteOne(filter: unknown): Promise<{
        deletedCount: number;
    }>;
    deleteMany(filter: unknown): Promise<{
        deletedCount: number;
    }>;
}
interface MongoCursor {
    sort(spec: Record<string, number>): MongoCursor;
    toArray(): Promise<MongoDocument[]>;
}
type MongoDocument = Record<string, unknown> & {
    _id: unknown;
};

export { MongoDBAdapter };

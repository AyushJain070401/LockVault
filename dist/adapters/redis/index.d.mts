import { D as DatabaseAdapter, S as Session, e as OAuthLink } from '../../index-BPNrRCYx.mjs';

/**
 * Redis adapter using `ioredis`.
 *
 * Uses hash maps and sets for efficient storage. Session and token
 * expiration leverages Redis TTL for automatic cleanup.
 */
declare class RedisAdapter implements DatabaseAdapter {
    private redis;
    private prefix;
    constructor(redis: RedisClient, options?: {
        prefix?: string;
    });
    private key;
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
    private deserializeSession;
}
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

export { RedisAdapter };

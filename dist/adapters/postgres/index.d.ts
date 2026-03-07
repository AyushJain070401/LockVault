import { D as DatabaseAdapter, S as Session, e as OAuthLink } from '../../index-BPNrRCYx.js';

/**
 * PostgreSQL adapter using the `pg` driver.
 *
 * Expects a `pg.Pool` instance. Call `initialize()` to auto-create tables.
 */
declare class PostgresAdapter implements DatabaseAdapter {
    private pool;
    private tablePrefix;
    constructor(pool: PgPool, options?: {
        tablePrefix?: string;
    });
    private t;
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
    private mapSession;
}
interface PgPool {
    query(text: string, values?: unknown[]): Promise<{
        rows: PgRow[];
        rowCount: number | null;
    }>;
    end(): Promise<void>;
}
type PgRow = Record<string, unknown>;

export { PostgresAdapter };

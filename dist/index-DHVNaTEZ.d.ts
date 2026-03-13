import { g as TokenPair, A as AccessTokenPayload, n as RefreshTokenPayload, k as DecodedToken, L as LockVaultConfig, l as LockVaultHooks, f as DeviceInfo, S as Session } from './index-BR3ae_bk.js';

interface JWTManager {
    createTokenPair(userId: string, customClaims?: Record<string, unknown>, sessionId?: string): Promise<TokenPair>;
    verifyAccessToken(token: string): Promise<AccessTokenPayload>;
    verifyRefreshToken(token: string): Promise<RefreshTokenPayload>;
    refreshTokens(refreshToken: string, customClaims?: Record<string, unknown>): Promise<TokenPair>;
    revokeToken(token: string): Promise<void>;
    rotateKeys(newSecret: string): void;
    decode(token: string): DecodedToken;
}
declare function createJWTManager(config: LockVaultConfig, hooks?: Partial<LockVaultHooks>): JWTManager;

interface SessionManager {
    createSession(userId: string, refreshTokenFamily: string, options?: {
        deviceInfo?: DeviceInfo;
        ipAddress?: string;
        metadata?: Record<string, unknown>;
        expiresInSeconds?: number;
    }): Promise<Session>;
    getSession(sessionId: string): Promise<Session>;
    touchSession(sessionId: string): Promise<Session | null>;
    getUserSessions(userId: string): Promise<Session[]>;
    revokeSession(sessionId: string): Promise<boolean>;
    revokeAllSessions(userId: string): Promise<number>;
    cleanup(): Promise<number>;
}
declare function createSessionManager(config: LockVaultConfig, hooks?: Partial<LockVaultHooks>): SessionManager;

export { type JWTManager as J, type SessionManager as S, createSessionManager as a, createJWTManager as c };

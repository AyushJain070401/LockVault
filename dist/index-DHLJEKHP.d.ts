import { L as LockVaultConfig, l as LockVaultHooks, g as TokenPair, A as AccessTokenPayload, n as RefreshTokenPayload, k as DecodedToken, f as DeviceInfo, S as Session } from './index-BPNrRCYx.js';

declare class JWTManager {
    private readonly config;
    private readonly adapter;
    private readonly hooks;
    private previousSecrets;
    constructor(config: LockVaultConfig, hooks?: Partial<LockVaultHooks>);
    private static readonly ASYMMETRIC_ALGS;
    private validateConfig;
    createTokenPair(userId: string, customClaims?: Record<string, unknown>, sessionId?: string): Promise<TokenPair>;
    verifyAccessToken(token: string): Promise<AccessTokenPayload>;
    verifyRefreshToken(token: string): Promise<RefreshTokenPayload>;
    refreshTokens(refreshToken: string, customClaims?: Record<string, unknown>): Promise<TokenPair>;
    revokeToken(token: string): Promise<void>;
    rotateKeys(newSecret: string): void;
    decode(token: string): DecodedToken;
    private sign;
    private verify;
    private verifySignature;
}

declare class SessionManager {
    private readonly config;
    private readonly adapter;
    private readonly hooks;
    constructor(config: LockVaultConfig, hooks?: Partial<LockVaultHooks>);
    /**
     * Create a new session for a user
     */
    createSession(userId: string, refreshTokenFamily: string, options?: {
        deviceInfo?: DeviceInfo;
        ipAddress?: string;
        metadata?: Record<string, unknown>;
        expiresInSeconds?: number;
    }): Promise<Session>;
    /**
     * Get a session by ID
     */
    getSession(sessionId: string): Promise<Session>;
    /**
     * Touch/renew a session (update lastActiveAt)
     */
    touchSession(sessionId: string): Promise<Session | null>;
    /**
     * Get all active sessions for a user
     */
    getUserSessions(userId: string): Promise<Session[]>;
    /**
     * Revoke a specific session
     */
    revokeSession(sessionId: string): Promise<boolean>;
    /**
     * Revoke all sessions for a user
     */
    revokeAllSessions(userId: string): Promise<number>;
    /**
     * Clean up expired sessions
     */
    cleanup(): Promise<number>;
}

export { JWTManager as J, SessionManager as S };

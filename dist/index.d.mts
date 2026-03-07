import { T as TOTPConfig, D as DatabaseAdapter, K as KeyValueStore, a as TOTPSetupResult, O as OAuthProviderConfig, b as OAuthProviderPreset, c as OAuthUserProfile, d as OAuthTokenResponse, e as OAuthLink, L as LockVaultConfig, f as DeviceInfo, g as TokenPair, S as Session } from './index-BPNrRCYx.mjs';
export { A as AccessTokenPayload, h as Algorithm, i as AuthErrorCode, j as AuthUser, C as CookieOptions, k as DecodedToken, l as LockVaultHooks, m as LockVaultPlugin, M as MiddlewareOptions, R as RateLimitConfig, n as RefreshTokenPayload, o as TokenPayload } from './index-BPNrRCYx.mjs';
import { J as JWTManager, S as SessionManager } from './index-CQV8FdRX.mjs';
import { L as LockVaultError } from './errors-BvUXMuaK.mjs';
export { C as ConfigurationError, O as OAuthError, R as RefreshTokenReuseError, S as SessionError, T as TOTPError, a as TokenExpiredError, b as TokenInvalidError, c as TokenRevokedError } from './errors-BvUXMuaK.mjs';

declare class TOTPManager {
    private readonly config;
    private readonly adapter;
    private readonly rateLimiter;
    private readonly replayStore;
    constructor(config: Partial<TOTPConfig> | undefined, adapter: DatabaseAdapter, kvStore?: KeyValueStore);
    /**
     * Generate a new TOTP setup for a user (secret + otpauth URI + backup codes)
     */
    setup(userId: string, userEmail?: string): Promise<TOTPSetupResult>;
    /**
     * Confirm TOTP setup — verify a code, then persist the secret + backup codes
     */
    confirmSetup(userId: string, secret: string, code: string, backupCodes: string[]): Promise<boolean>;
    /**
     * Verify a TOTP code for a user.
     * Rate-limited to 5 attempts per minute per user to prevent brute-force.
     */
    verify(userId: string, code: string): Promise<boolean>;
    /**
     * Disable TOTP for a user
     */
    disable(userId: string): Promise<void>;
    /**
     * Get remaining backup codes count
     */
    getBackupCodesCount(userId: string): Promise<number>;
    /**
     * Regenerate backup codes
     */
    regenerateBackupCodes(userId: string): Promise<string[]>;
    private generateSecret;
    private buildURI;
    /**
     * Core TOTP code generation (RFC 6238)
     */
    generateCode(secret: string, time?: number): string;
    /**
     * Verify a TOTP code with time window tolerance.
     * Uses timing-safe comparison to prevent timing attacks.
     */
    private verifyCode;
    /**
     * HOTP generation (RFC 4226)
     */
    private hotpGenerate;
}

declare class OAuthManager {
    private readonly providers;
    private readonly adapter;
    private readonly stateStore;
    private readonly ownsStateStore;
    constructor(providerConfigs: Record<string, OAuthProviderConfig> | undefined, adapter: DatabaseAdapter, stateStore?: KeyValueStore);
    /**
     * Clean up internal resources. Only destroys the state store if it was
     * created internally (not user-provided).
     */
    destroy(): void;
    /**
     * Register a provider using a preset (Google, GitHub, etc.)
     */
    registerPreset(preset: OAuthProviderPreset, config: {
        clientId: string;
        clientSecret: string;
        redirectUri: string;
        scopes?: string[];
    }): void;
    /**
     * Register a custom OAuth provider
     */
    registerProvider(name: string, config: OAuthProviderConfig): void;
    /**
     * Generate the authorization URL for redirect
     */
    getAuthorizationUrl(providerName: string, options?: {
        state?: string;
        metadata?: Record<string, unknown>;
    }): Promise<string>;
    /**
     * Handle the OAuth callback — exchange code for tokens and fetch profile
     */
    handleCallback(providerName: string, code: string, state: string): Promise<{
        profile: OAuthUserProfile;
        tokens: OAuthTokenResponse;
    }>;
    /**
     * Link an OAuth account to an existing user
     */
    linkAccount(userId: string, providerName: string, profile: OAuthUserProfile, tokens: OAuthTokenResponse): Promise<void>;
    /**
     * Find an existing user by their OAuth identity
     */
    findUserByOAuth(providerName: string, providerUserId: string): Promise<string | null>;
    /**
     * Unlink an OAuth provider from a user
     */
    unlinkAccount(userId: string, providerName: string): Promise<boolean>;
    /**
     * Get all linked OAuth providers for a user
     */
    getLinkedProviders(userId: string): Promise<OAuthLink[]>;
    private getProvider;
    private exchangeCode;
    private fetchProfile;
}

declare class LockVault {
    readonly jwt: JWTManager;
    readonly sessions: SessionManager;
    readonly totp: TOTPManager;
    readonly oauth: OAuthManager;
    readonly adapter: DatabaseAdapter;
    private readonly config;
    private readonly hooks;
    private cleanupInterval?;
    constructor(config: LockVaultConfig);
    initialize(): Promise<void>;
    /**
     * Start automatic cleanup of expired sessions and revocation entries.
     */
    startCleanup(intervalMs?: number): void;
    stopCleanup(): void;
    /**
     * Authenticate a user and create a full token pair + session.
     */
    login(userId: string, options?: {
        customClaims?: Record<string, unknown>;
        deviceInfo?: DeviceInfo;
        ipAddress?: string;
        metadata?: Record<string, unknown>;
    }): Promise<{
        tokens: TokenPair;
        session: Session;
    }>;
    /**
     * Refresh tokens with automatic rotation.
     */
    refresh(refreshToken: string, customClaims?: Record<string, unknown>): Promise<TokenPair>;
    /**
     * Logout — revoke the token and session.
     */
    logout(accessToken: string): Promise<void>;
    /**
     * Logout from all devices — revoke all sessions.
     */
    logoutAll(userId: string): Promise<number>;
    setupTOTP(userId: string, email?: string): Promise<TOTPSetupResult>;
    confirmTOTP(userId: string, secret: string, code: string, backupCodes: string[]): Promise<boolean>;
    verifyTOTP(userId: string, code: string): Promise<boolean>;
    disableTOTP(userId: string): Promise<void>;
    registerOAuthProvider(name: string, config: OAuthProviderConfig): void;
    registerOAuthPreset(preset: OAuthProviderPreset, config: {
        clientId: string;
        clientSecret: string;
        redirectUri: string;
    }): void;
    getOAuthAuthorizationUrl(provider: string, metadata?: Record<string, unknown>): Promise<string>;
    handleOAuthCallback(provider: string, code: string, state: string): Promise<{
        profile: OAuthUserProfile;
        tokens: OAuthTokenResponse;
    }>;
    rotateJWTKeys(newSecret: string): void;
    close(): Promise<void>;
    private static readonly ASYMMETRIC_ALGS;
    private validateAndNormalize;
    private mergePluginHooks;
}

/**
 * In-memory adapter for testing and development.
 * Also serves as the reference implementation for custom adapters.
 */
declare class MemoryAdapter implements DatabaseAdapter {
    private sessions;
    private refreshFamilies;
    private revocationList;
    private totpSecrets;
    private backupCodes;
    private oauthLinks;
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
    initialize(): Promise<void>;
    close(): Promise<void>;
}

/**
 * Default in-memory key-value store with TTL support.
 *
 * Works for single-instance deployments. For multi-instance or serverless
 * setups, provide a Redis-backed or database-backed KeyValueStore.
 */
declare class MemoryKeyValueStore implements KeyValueStore {
    private store;
    private cleanupTimer?;
    private readonly maxEntries;
    constructor(options?: {
        maxEntries?: number;
        cleanupIntervalMs?: number;
    });
    get(key: string): Promise<string | null>;
    set(key: string, value: string, ttlMs?: number): Promise<void>;
    delete(key: string): Promise<boolean>;
    private cleanup;
    destroy(): void;
}

declare class RateLimitError extends LockVaultError {
    readonly retryAfterMs: number;
    constructor(identifier: string, retryAfterMs: number);
}
interface RateLimiterConfig {
    /** Time window in milliseconds (default: 60_000 = 1 minute) */
    windowMs: number;
    /** Maximum number of attempts allowed within the window (default: 5) */
    maxAttempts: number;
    /** Optional callback when rate limit is hit */
    onRateLimit?: (identifier: string) => void | Promise<void>;
}
/**
 * Sliding-window in-memory rate limiter.
 *
 * Tracks attempts per identifier (e.g., userId, IP address) and throws
 * `RateLimitError` when the limit is exceeded. Automatically cleans up
 * stale entries to prevent memory leaks.
 */
declare class RateLimiter {
    private readonly config;
    private readonly store;
    private cleanupTimer?;
    constructor(config?: Partial<RateLimiterConfig>);
    /**
     * Check and consume one attempt for the given identifier.
     * Throws `RateLimitError` if the limit is exceeded.
     */
    consume(identifier: string): Promise<void>;
    /**
     * Reset the rate limit counter for a given identifier (e.g., after successful auth).
     */
    reset(identifier: string): void;
    /**
     * Get remaining attempts for an identifier.
     */
    remaining(identifier: string): number;
    /**
     * Clean up expired entries to prevent memory leaks.
     */
    cleanup(): void;
    /**
     * Stop the cleanup timer and clear internal state.
     */
    destroy(): void;
}

/**
 * Generate a cryptographically secure random string
 */
declare function generateId(length?: number): string;
/**
 * Generate a UUID v4
 */
declare function generateUUID(): string;
/**
 * Hash a password using scrypt
 */
declare function hashPassword(password: string): Promise<string>;
/**
 * Verify a password against its hash
 */
declare function verifyPassword(password: string, hash: string): Promise<boolean>;
/**
 * Generate backup codes for 2FA
 */
declare function generateBackupCodes(count?: number): string[];

export { DatabaseAdapter, DeviceInfo, JWTManager, KeyValueStore, LockVault, LockVaultConfig, LockVaultError, MemoryAdapter, MemoryKeyValueStore, OAuthLink, OAuthManager, OAuthProviderConfig, OAuthProviderPreset, OAuthTokenResponse, OAuthUserProfile, RateLimitError, RateLimiter, type RateLimiterConfig, Session, SessionManager, TOTPConfig, TOTPManager, TOTPSetupResult, TokenPair, generateBackupCodes, generateId, generateUUID, hashPassword, verifyPassword };

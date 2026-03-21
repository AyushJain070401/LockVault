import { T as TOTPSetupResult, a as TOTPConfig, D as DatabaseAdapter, K as KeyValueStore, O as OAuthProviderPreset, b as OAuthProviderConfig, c as OAuthUserProfile, d as OAuthTokenResponse, e as OAuthLink, f as DeviceInfo, g as TokenPair, S as Session, L as LockVaultConfig } from './index-BR3ae_bk.js';
export { A as AccessTokenPayload, h as Algorithm, i as AuthErrorCode, j as AuthUser, C as CookieOptions, k as DecodedToken, l as LockVaultHooks, m as LockVaultPlugin, M as MiddlewareOptions, R as RateLimitConfig, n as RefreshTokenPayload, o as TokenPayload } from './index-BR3ae_bk.js';
import { J as JWTManager, S as SessionManager } from './index-BxZvBPS6.js';
export { c as createJWTManager, a as createSessionManager } from './index-BxZvBPS6.js';
import { L as LockVaultError } from './errors-B26T9cZh.js';
export { C as ConfigurationError, E as EmailError, O as OAuthError, R as RefreshTokenReuseError, S as SessionError, T as TOTPError, a as TokenExpiredError, b as TokenInvalidError, c as TokenRevokedError } from './errors-B26T9cZh.js';
export { A as AlertEmailVars, a as AlertTheme, B as BulkEmailResult, C as CustomRenderFn, E as EmailConfig, b as EmailResult, c as EmailTemplateCategory, F as ForgotPasswordEmailVars, d as ForgotPasswordTheme, L as LoginEmailVars, e as LoginTheme, M as MagicLinkEmailVars, S as SMTPConfig, f as SendBulkOptions, g as SendCustomTemplateOptions, h as SendEmailOptions, i as SendNamedTemplateOptions, j as SendTemplateEmailOptions, T as TemplateDefinition, k as TemplateSource, V as VerificationEmailVars, W as WelcomeEmailVars } from './types-DBHV5yQn.js';

interface TOTPManager {
    setup(userId: string, userEmail?: string): Promise<TOTPSetupResult>;
    confirmSetup(userId: string, secret: string, code: string, backupCodes: string[]): Promise<boolean>;
    verify(userId: string, code: string): Promise<boolean>;
    disable(userId: string): Promise<void>;
    getBackupCodesCount(userId: string): Promise<number>;
    regenerateBackupCodes(userId: string): Promise<string[]>;
    generateCode(secret: string, time?: number): string;
    destroy(): void;
}
declare function createTOTPManager(cfg: Partial<TOTPConfig> | undefined, adapter: DatabaseAdapter, kvStore?: KeyValueStore): TOTPManager;

interface OAuthManager {
    destroy(): void;
    registerPreset(preset: OAuthProviderPreset, config: {
        clientId: string;
        clientSecret: string;
        redirectUri: string;
        scopes?: string[];
    }): void;
    registerProvider(name: string, config: OAuthProviderConfig): void;
    getAuthorizationUrl(providerName: string, options?: {
        state?: string;
        metadata?: Record<string, unknown>;
    }): Promise<string>;
    handleCallback(providerName: string, code: string, state: string): Promise<{
        profile: OAuthUserProfile;
        tokens: OAuthTokenResponse;
    }>;
    linkAccount(userId: string, providerName: string, profile: OAuthUserProfile, tokens: OAuthTokenResponse): Promise<void>;
    findUserByOAuth(providerName: string, providerUserId: string): Promise<string | null>;
    unlinkAccount(userId: string, providerName: string): Promise<boolean>;
    getLinkedProviders(userId: string): Promise<OAuthLink[]>;
}
declare function createOAuthManager(providerConfigs: Record<string, OAuthProviderConfig> | undefined, adapter: DatabaseAdapter, externalStateStore?: KeyValueStore): OAuthManager;

interface LockVault {
    readonly jwt: JWTManager;
    readonly sessions: SessionManager;
    readonly totp: TOTPManager;
    readonly oauth: OAuthManager;
    readonly adapter: DatabaseAdapter;
    initialize(): Promise<void>;
    startCleanup(intervalMs?: number): void;
    stopCleanup(): void;
    login(userId: string, options?: {
        customClaims?: Record<string, unknown>;
        deviceInfo?: DeviceInfo;
        ipAddress?: string;
        metadata?: Record<string, unknown>;
    }): Promise<{
        tokens: TokenPair;
        session: Session;
    }>;
    refresh(refreshToken: string, customClaims?: Record<string, unknown>): Promise<TokenPair>;
    logout(accessToken: string): Promise<void>;
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
}
declare function createLockVault(config: LockVaultConfig): LockVault;

declare function createMemoryAdapter(): DatabaseAdapter;

/**
 * Create an in-memory key-value store with TTL support.
 */
declare function createMemoryKeyValueStore(options?: {
    maxEntries?: number;
    cleanupIntervalMs?: number;
}): KeyValueStore & {
    destroy(): void;
};

declare class RateLimitError extends LockVaultError {
    readonly retryAfterMs: number;
    constructor(identifier: string, retryAfterMs: number);
}
interface RateLimiterConfig {
    windowMs: number;
    maxAttempts: number;
    onRateLimit?: (identifier: string) => void | Promise<void>;
}
interface RateLimiter {
    consume(identifier: string): Promise<void>;
    reset(identifier: string): void;
    remaining(identifier: string): number;
    cleanup(): void;
    destroy(): void;
}
declare function createRateLimiter(config?: Partial<RateLimiterConfig>): RateLimiter;

/**
 * Generate a cryptographically secure random string
 */
declare function generateId(length?: number): string;
/**
 * Generate a UUID v4
 */
declare function generateUUID(): string;
/**
 * Hash a password using scrypt with hardened parameters.
 *
 * Output format: `scrypt:N:r:p:salt:derivedKey`
 * Embedding the parameters allows future cost upgrades without
 * breaking existing hashes.
 */
declare function hashPassword(password: string, options?: {
    N?: number;
    r?: number;
    p?: number;
}): Promise<string>;
/**
 * Verify a password against its hash.
 * Supports both new format (scrypt:N:r:p:salt:key) and legacy (salt:key).
 */
declare function verifyPassword(password: string, hash: string): Promise<boolean>;
/**
 * Generate backup codes for 2FA
 */
declare function generateBackupCodes(count?: number): string[];
/**
 * Generate a token fingerprint from client context (IP + User-Agent).
 * Binds tokens to the client that created them, mitigating token theft.
 * Uses a one-way hash so the fingerprint can't be reversed.
 */
declare function generateTokenFingerprint(ipAddress?: string, userAgent?: string): string;
/**
 * Validate and sanitize an IP address.
 * Returns the sanitized IP or undefined if invalid.
 */
declare function sanitizeIpAddress(ip: string | undefined): string | undefined;
/**
 * Generate a PKCE code verifier and challenge pair for OAuth.
 * @see https://datatracker.ietf.org/doc/html/rfc7636
 */
declare function generatePKCE(): {
    codeVerifier: string;
    codeChallenge: string;
    codeChallengeMethod: 'S256';
};
/**
 * Generate a CSRF token.
 */
declare function generateCSRFToken(): string;

export { DatabaseAdapter, DeviceInfo, JWTManager, KeyValueStore, type LockVault, LockVaultConfig, LockVaultError, OAuthLink, type OAuthManager, OAuthProviderConfig, OAuthProviderPreset, OAuthTokenResponse, OAuthUserProfile, RateLimitError, type RateLimiter, type RateLimiterConfig, Session, SessionManager, TOTPConfig, type TOTPManager, TOTPSetupResult, TokenPair, createLockVault, createMemoryAdapter, createMemoryKeyValueStore, createOAuthManager, createRateLimiter, createTOTPManager, generateBackupCodes, generateCSRFToken, generateId, generatePKCE, generateTokenFingerprint, generateUUID, hashPassword, sanitizeIpAddress, verifyPassword };

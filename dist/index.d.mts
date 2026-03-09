import { T as TOTPSetupResult, a as TOTPConfig, D as DatabaseAdapter, K as KeyValueStore, O as OAuthProviderPreset, b as OAuthProviderConfig, c as OAuthUserProfile, d as OAuthTokenResponse, e as OAuthLink, f as DeviceInfo, g as TokenPair, S as Session, L as LockVaultConfig } from './index-BN-tpFRY.mjs';
export { A as AccessTokenPayload, h as Algorithm, i as AuthErrorCode, j as AuthUser, C as CookieOptions, k as DecodedToken, l as LockVaultHooks, m as LockVaultPlugin, M as MiddlewareOptions, R as RateLimitConfig, n as RefreshTokenPayload, o as TokenPayload } from './index-BN-tpFRY.mjs';
import { J as JWTManager, S as SessionManager } from './index-CBgAYknw.mjs';
export { c as createJWTManager, a as createSessionManager } from './index-CBgAYknw.mjs';
import { L as LockVaultError } from './errors-sWvs0-1o.mjs';
export { C as ConfigurationError, E as EmailError, O as OAuthError, R as RefreshTokenReuseError, S as SessionError, T as TOTPError, a as TokenExpiredError, b as TokenInvalidError, c as TokenRevokedError } from './errors-sWvs0-1o.mjs';
export { A as AlertEmailVars, a as AlertTheme, B as BulkEmailResult, C as CustomRenderFn, E as EmailConfig, b as EmailResult, c as EmailTemplateCategory, F as ForgotPasswordEmailVars, d as ForgotPasswordTheme, L as LoginEmailVars, e as LoginTheme, M as MagicLinkEmailVars, S as SMTPConfig, f as SendBulkOptions, g as SendCustomTemplateOptions, h as SendEmailOptions, i as SendNamedTemplateOptions, j as SendTemplateEmailOptions, T as TemplateDefinition, k as TemplateSource, V as VerificationEmailVars, W as WelcomeEmailVars } from './types-1dgdkzJw.mjs';

interface TOTPManager {
    setup(userId: string, userEmail?: string): Promise<TOTPSetupResult>;
    confirmSetup(userId: string, secret: string, code: string, backupCodes: string[]): Promise<boolean>;
    verify(userId: string, code: string): Promise<boolean>;
    disable(userId: string): Promise<void>;
    getBackupCodesCount(userId: string): Promise<number>;
    regenerateBackupCodes(userId: string): Promise<string[]>;
    generateCode(secret: string, time?: number): string;
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

export { DatabaseAdapter, DeviceInfo, JWTManager, KeyValueStore, type LockVault, LockVaultConfig, LockVaultError, OAuthLink, type OAuthManager, OAuthProviderConfig, OAuthProviderPreset, OAuthTokenResponse, OAuthUserProfile, RateLimitError, type RateLimiter, type RateLimiterConfig, Session, SessionManager, TOTPConfig, type TOTPManager, TOTPSetupResult, TokenPair, createLockVault, createMemoryAdapter, createMemoryKeyValueStore, createOAuthManager, createRateLimiter, createTOTPManager, generateBackupCodes, generateId, generateUUID, hashPassword, verifyPassword };

type Algorithm = 'HS256' | 'RS256';
interface TokenPayload {
    sub: string;
    iat: number;
    nbf?: number;
    exp: number;
    jti: string;
    type: 'access' | 'refresh';
    [key: string]: unknown;
}
interface AccessTokenPayload extends TokenPayload {
    type: 'access';
}
interface RefreshTokenPayload extends TokenPayload {
    type: 'refresh';
    family: string;
    generation: number;
}
interface TokenPair {
    accessToken: string;
    refreshToken: string;
    accessTokenExpiresAt: Date;
    refreshTokenExpiresAt: Date;
}
interface DecodedToken<T extends TokenPayload = TokenPayload> {
    header: {
        alg: Algorithm;
        typ: 'JWT';
    };
    payload: T;
    signature: string;
}
interface Session {
    id: string;
    userId: string;
    refreshTokenFamily: string;
    deviceInfo?: DeviceInfo;
    ipAddress?: string;
    createdAt: Date;
    expiresAt: Date;
    lastActiveAt: Date;
    isRevoked: boolean;
    metadata?: Record<string, unknown>;
}
interface DeviceInfo {
    userAgent?: string;
    deviceName?: string;
    deviceType?: 'desktop' | 'mobile' | 'tablet' | 'unknown';
    os?: string;
    browser?: string;
}
interface AuthUser {
    id: string;
    email?: string;
    passwordHash?: string;
    totpSecret?: string | null;
    totpEnabled: boolean;
    backupCodes?: string[];
    oauthProviders?: OAuthLink[];
    metadata?: Record<string, unknown>;
}
interface OAuthLink {
    provider: string;
    providerUserId: string;
    accessToken?: string;
    refreshToken?: string;
    profile?: Record<string, unknown>;
    linkedAt: Date;
}
interface TOTPConfig {
    issuer: string;
    algorithm?: 'SHA1' | 'SHA256' | 'SHA512';
    digits?: number;
    period?: number;
    window?: number;
}
interface TOTPSetupResult {
    /** Base32-encoded TOTP secret */
    secret: string;
    /** otpauth:// URI — pass this to a QR code library (e.g. `qrcode`) to generate a scannable image */
    uri: string;
    /** One-time backup codes for account recovery */
    backupCodes: string[];
}
interface OAuthProviderConfig {
    clientId: string;
    clientSecret: string;
    redirectUri: string;
    scopes?: string[];
    authorizationUrl: string;
    tokenUrl: string;
    userInfoUrl: string;
    mapProfile: (profile: Record<string, unknown>) => OAuthUserProfile;
}
interface OAuthUserProfile {
    id: string;
    email?: string;
    name?: string;
    avatar?: string;
    raw: Record<string, unknown>;
}
interface OAuthTokenResponse {
    access_token: string;
    refresh_token?: string;
    token_type: string;
    expires_in?: number;
    scope?: string;
}
type OAuthProviderPreset = 'google' | 'github' | 'facebook' | 'apple' | 'microsoft';
interface DatabaseAdapter {
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
    initialize?(): Promise<void>;
    close?(): Promise<void>;
}
interface LockVaultConfig {
    jwt: {
        algorithm?: Algorithm;
        accessTokenSecret: string;
        refreshTokenSecret?: string;
        accessTokenTTL?: number;
        refreshTokenTTL?: number;
        issuer?: string;
        audience?: string;
        privateKey?: string;
        publicKey?: string;
    };
    session?: {
        enabled?: boolean;
        maxPerUser?: number;
        inactivityTimeout?: number;
    };
    refreshToken?: {
        rotation?: boolean;
        reuseDetection?: boolean;
        familyRevocationOnReuse?: boolean;
        encryption?: {
            enabled: boolean;
            key: string;
        };
    };
    totp?: TOTPConfig;
    oauth?: {
        providers: Record<string, OAuthProviderConfig>;
    };
    security?: {
        cookieOptions?: CookieOptions;
        csrfProtection?: boolean;
        rateLimiting?: RateLimitConfig;
    };
    adapter: DatabaseAdapter;
    plugins?: LockVaultPlugin[];
}
interface CookieOptions {
    httpOnly?: boolean;
    secure?: boolean;
    sameSite?: 'strict' | 'lax' | 'none';
    domain?: string;
    path?: string;
    maxAge?: number;
}
interface RateLimitConfig {
    windowMs: number;
    maxAttempts: number;
    onRateLimit?: (identifier: string) => void | Promise<void>;
}
interface LockVaultPlugin {
    name: string;
    version?: string;
    hooks?: Partial<LockVaultHooks>;
}
interface LockVaultHooks {
    beforeTokenCreate: (payload: Record<string, unknown>) => Record<string, unknown> | Promise<Record<string, unknown>>;
    afterTokenCreate: (tokenPair: TokenPair) => void | Promise<void>;
    beforeTokenVerify: (token: string) => string | Promise<string>;
    afterTokenVerify: (payload: TokenPayload) => void | Promise<void>;
    beforeSessionCreate: (session: Partial<Session>) => Partial<Session> | Promise<Partial<Session>>;
    afterSessionCreate: (session: Session) => void | Promise<void>;
    onTokenRevoked: (jti: string) => void | Promise<void>;
    onReuseDetected: (family: string, userId: string) => void | Promise<void>;
    onError: (error: Error, context: string) => void | Promise<void>;
}
interface MiddlewareOptions {
    tokenExtractor?: (req: unknown) => string | null;
    onUnauthorized?: (req: unknown, res: unknown) => void;
    requireSession?: boolean;
    roles?: string[];
}
declare enum AuthErrorCode {
    TOKEN_EXPIRED = "TOKEN_EXPIRED",
    TOKEN_INVALID = "TOKEN_INVALID",
    TOKEN_REVOKED = "TOKEN_REVOKED",
    TOKEN_MALFORMED = "TOKEN_MALFORMED",
    REFRESH_TOKEN_REUSE = "REFRESH_TOKEN_REUSE",
    SESSION_EXPIRED = "SESSION_EXPIRED",
    SESSION_NOT_FOUND = "SESSION_NOT_FOUND",
    SESSION_REVOKED = "SESSION_REVOKED",
    MAX_SESSIONS_REACHED = "MAX_SESSIONS_REACHED",
    TOTP_INVALID = "TOTP_INVALID",
    TOTP_NOT_ENABLED = "TOTP_NOT_ENABLED",
    TOTP_ALREADY_ENABLED = "TOTP_ALREADY_ENABLED",
    BACKUP_CODE_INVALID = "BACKUP_CODE_INVALID",
    OAUTH_ERROR = "OAUTH_ERROR",
    OAUTH_STATE_MISMATCH = "OAUTH_STATE_MISMATCH",
    ADAPTER_ERROR = "ADAPTER_ERROR",
    CONFIGURATION_ERROR = "CONFIGURATION_ERROR",
    RATE_LIMITED = "RATE_LIMITED",
    ENCRYPTION_ERROR = "ENCRYPTION_ERROR"
}

export { type AccessTokenPayload as A, type CookieOptions as C, type DatabaseAdapter as D, type LockVaultConfig as L, type MiddlewareOptions as M, type OAuthProviderConfig as O, type RateLimitConfig as R, type Session as S, type TOTPConfig as T, type TOTPSetupResult as a, type OAuthProviderPreset as b, type OAuthUserProfile as c, type OAuthTokenResponse as d, type OAuthLink as e, type DeviceInfo as f, type TokenPair as g, type Algorithm as h, AuthErrorCode as i, type AuthUser as j, type DecodedToken as k, type LockVaultHooks as l, type LockVaultPlugin as m, type RefreshTokenPayload as n, type TokenPayload as o };

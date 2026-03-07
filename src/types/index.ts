// ─── Token Types ────────────────────────────────────────────────────────────

export type Algorithm = 'HS256' | 'RS256' | 'ES256' | 'ES384' | 'ES512' | 'EdDSA';

export interface TokenPayload {
  sub: string;
  iat: number;
  nbf?: number;
  exp: number;
  jti: string;
  type: 'access' | 'refresh';
  [key: string]: unknown;
}

export interface AccessTokenPayload extends TokenPayload {
  type: 'access';
}

export interface RefreshTokenPayload extends TokenPayload {
  type: 'refresh';
  family: string;
  generation: number;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  accessTokenExpiresAt: Date;
  refreshTokenExpiresAt: Date;
}

export interface DecodedToken<T extends TokenPayload = TokenPayload> {
  header: { alg: Algorithm; typ: 'JWT' };
  payload: T;
  signature: string;
}

// ─── Session Types ──────────────────────────────────────────────────────────

export interface Session {
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

export interface DeviceInfo {
  userAgent?: string;
  deviceName?: string;
  deviceType?: 'desktop' | 'mobile' | 'tablet' | 'unknown';
  os?: string;
  browser?: string;
}

// ─── User Types ─────────────────────────────────────────────────────────────

export interface AuthUser {
  id: string;
  email?: string;
  passwordHash?: string;
  totpSecret?: string | null;
  totpEnabled: boolean;
  backupCodes?: string[];
  oauthProviders?: OAuthLink[];
  metadata?: Record<string, unknown>;
}

export interface OAuthLink {
  provider: string;
  providerUserId: string;
  accessToken?: string;
  refreshToken?: string;
  profile?: Record<string, unknown>;
  linkedAt: Date;
}

// ─── TOTP Types ─────────────────────────────────────────────────────────────

export interface TOTPConfig {
  issuer: string;
  algorithm?: 'SHA1' | 'SHA256' | 'SHA512';
  digits?: number;
  period?: number;
  window?: number;
}

export interface TOTPSetupResult {
  /** Base32-encoded TOTP secret */
  secret: string;
  /** otpauth:// URI — pass this to a QR code library (e.g. `qrcode`) to generate a scannable image */
  uri: string;
  /** One-time backup codes for account recovery */
  backupCodes: string[];
}

// ─── OAuth Types ────────────────────────────────────────────────────────────

export interface OAuthProviderConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scopes?: string[];
  authorizationUrl: string;
  tokenUrl: string;
  userInfoUrl: string;
  mapProfile: (profile: Record<string, unknown>) => OAuthUserProfile;
}

export interface OAuthUserProfile {
  id: string;
  email?: string;
  name?: string;
  avatar?: string;
  raw: Record<string, unknown>;
}

export interface OAuthTokenResponse {
  access_token: string;
  refresh_token?: string;
  token_type: string;
  expires_in?: number;
  scope?: string;
}

export type OAuthProviderPreset = 'google' | 'github' | 'facebook' | 'apple' | 'microsoft';

// ─── Key-Value Store Interface (for OAuth state, TOTP replay, etc.) ─────────

/**
 * A simple key-value store interface for ephemeral data like OAuth state
 * tokens and TOTP replay tracking. The default in-memory implementation
 * works for single-instance deployments. For multi-instance or serverless
 * setups, provide a Redis or database-backed implementation.
 */
export interface KeyValueStore {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ttlMs?: number): Promise<void>;
  delete(key: string): Promise<boolean>;
}

// ─── Adapter Interface ──────────────────────────────────────────────────────

export interface DatabaseAdapter {
  // Session operations
  createSession(session: Session): Promise<Session>;
  getSession(sessionId: string): Promise<Session | null>;
  getSessionsByUser(userId: string): Promise<Session[]>;
  updateSession(sessionId: string, updates: Partial<Session>): Promise<Session | null>;
  deleteSession(sessionId: string): Promise<boolean>;
  deleteSessionsByUser(userId: string): Promise<number>;
  deleteExpiredSessions(): Promise<number>;

  // Refresh token family tracking (for rotation/reuse detection)
  storeRefreshTokenFamily(family: string, userId: string, generation: number): Promise<void>;
  getRefreshTokenFamily(family: string): Promise<{ userId: string; generation: number; revoked: boolean } | null>;
  revokeRefreshTokenFamily(family: string): Promise<void>;
  incrementRefreshTokenGeneration(family: string): Promise<number>;

  // Token revocation list
  addToRevocationList(jti: string, expiresAt: Date): Promise<void>;
  isRevoked(jti: string): Promise<boolean>;
  cleanupRevocationList(): Promise<number>;

  // TOTP / 2FA
  storeTOTPSecret(userId: string, secret: string): Promise<void>;
  getTOTPSecret(userId: string): Promise<string | null>;
  removeTOTPSecret(userId: string): Promise<void>;
  storeBackupCodes(userId: string, codes: string[]): Promise<void>;
  getBackupCodes(userId: string): Promise<string[]>;
  consumeBackupCode(userId: string, code: string): Promise<boolean>;

  // OAuth account linking
  linkOAuthAccount(userId: string, link: OAuthLink): Promise<void>;
  getOAuthLinks(userId: string): Promise<OAuthLink[]>;
  findUserByOAuth(provider: string, providerUserId: string): Promise<string | null>;
  unlinkOAuthAccount(userId: string, provider: string): Promise<boolean>;

  // Lifecycle
  initialize?(): Promise<void>;
  close?(): Promise<void>;
}

// ─── Configuration ──────────────────────────────────────────────────────────

export interface LockVaultConfig {
  jwt: {
    algorithm?: Algorithm;
    accessTokenSecret: string;
    refreshTokenSecret?: string;
    accessTokenTTL?: number;        // seconds, default 900 (15min)
    refreshTokenTTL?: number;       // seconds, default 604800 (7 days)
    issuer?: string;
    audience?: string;
    privateKey?: string;            // for RS256, ES256, ES384, ES512, EdDSA
    publicKey?: string;             // for RS256, ES256, ES384, ES512, EdDSA
  };
  session?: {
    enabled?: boolean;
    maxPerUser?: number;            // max concurrent sessions
    inactivityTimeout?: number;     // seconds
  };
  refreshToken?: {
    rotation?: boolean;             // default true
    reuseDetection?: boolean;       // default true
    familyRevocationOnReuse?: boolean; // default true
    encryption?: {
      enabled: boolean;
      key: string;                  // 32-byte hex key
    };
  };
  totp?: TOTPConfig;
  oauth?: {
    providers: Record<string, OAuthProviderConfig>;
    /** Optional external state store for multi-instance deployments */
    stateStore?: KeyValueStore;
  };
  security?: {
    cookieOptions?: CookieOptions;
    csrfProtection?: boolean;
    rateLimiting?: RateLimitConfig;
  };
  /** Optional external key-value store for ephemeral data (TOTP replay, etc.) */
  kvStore?: KeyValueStore;
  adapter: DatabaseAdapter;
  plugins?: LockVaultPlugin[];
}

export interface CookieOptions {
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'strict' | 'lax' | 'none';
  domain?: string;
  path?: string;
  maxAge?: number;
}

export interface RateLimitConfig {
  windowMs: number;
  maxAttempts: number;
  onRateLimit?: (identifier: string) => void | Promise<void>;
}

// ─── Plugin System ──────────────────────────────────────────────────────────

export interface LockVaultPlugin {
  name: string;
  version?: string;
  hooks?: Partial<LockVaultHooks>;
}

export interface LockVaultHooks {
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

// ─── Middleware Types ───────────────────────────────────────────────────────

export interface AuthRequest {
  token?: string;
  user?: TokenPayload;
  session?: Session;
}

export interface MiddlewareOptions {
  tokenExtractor?: (req: unknown) => string | null;
  onUnauthorized?: (req: unknown, res: unknown) => void;
  requireSession?: boolean;
  roles?: string[];
}

// ─── Error Types ────────────────────────────────────────────────────────────

export enum AuthErrorCode {
  TOKEN_EXPIRED = 'TOKEN_EXPIRED',
  TOKEN_INVALID = 'TOKEN_INVALID',
  TOKEN_REVOKED = 'TOKEN_REVOKED',
  TOKEN_MALFORMED = 'TOKEN_MALFORMED',
  REFRESH_TOKEN_REUSE = 'REFRESH_TOKEN_REUSE',
  SESSION_EXPIRED = 'SESSION_EXPIRED',
  SESSION_NOT_FOUND = 'SESSION_NOT_FOUND',
  SESSION_REVOKED = 'SESSION_REVOKED',
  MAX_SESSIONS_REACHED = 'MAX_SESSIONS_REACHED',
  TOTP_INVALID = 'TOTP_INVALID',
  TOTP_NOT_ENABLED = 'TOTP_NOT_ENABLED',
  TOTP_ALREADY_ENABLED = 'TOTP_ALREADY_ENABLED',
  BACKUP_CODE_INVALID = 'BACKUP_CODE_INVALID',
  OAUTH_ERROR = 'OAUTH_ERROR',
  OAUTH_STATE_MISMATCH = 'OAUTH_STATE_MISMATCH',
  ADAPTER_ERROR = 'ADAPTER_ERROR',
  CONFIGURATION_ERROR = 'CONFIGURATION_ERROR',
  RATE_LIMITED = 'RATE_LIMITED',
  ENCRYPTION_ERROR = 'ENCRYPTION_ERROR',
}

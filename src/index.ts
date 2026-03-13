// ─── Core ────────────────────────────────────────────────────────────────
export { createLockVault } from './core/index.js';
export type { LockVault } from './core/index.js';

// ─── Modules ─────────────────────────────────────────────────────────────
export { createJWTManager } from './jwt/index.js';
export type { JWTManager } from './jwt/index.js';
export { createSessionManager } from './session/index.js';
export type { SessionManager } from './session/index.js';
export { createTOTPManager } from './totp/index.js';
export type { TOTPManager } from './totp/index.js';
export { createOAuthManager } from './oauth/index.js';
export type { OAuthManager } from './oauth/index.js';

// ─── Adapters ────────────────────────────────────────────────────────────
export { createMemoryAdapter } from './adapters/memory/index.js';
// Database-specific adapters are exported from sub-paths:
//   import { createPostgresAdapter } from 'lockvault/adapters/postgres';
//   import { createMongoDBAdapter }  from 'lockvault/adapters/mongodb';
//   import { createRedisAdapter }    from 'lockvault/adapters/redis';

// ─── Middleware ───────────────────────────────────────────────────────────
// Framework-specific middleware is exported from sub-paths:
//   import { authenticate, authorize } from 'lockvault/middleware/express';
//   import { lockVaultPlugin }         from 'lockvault/middleware/fastify';

// ─── Types ───────────────────────────────────────────────────────────────
export type {
  Algorithm, TokenPayload, AccessTokenPayload, RefreshTokenPayload, TokenPair,
  DecodedToken, Session, DeviceInfo, AuthUser, OAuthLink, TOTPConfig,
  TOTPSetupResult, OAuthProviderConfig, OAuthUserProfile, OAuthTokenResponse,
  OAuthProviderPreset, DatabaseAdapter, KeyValueStore, LockVaultConfig,
  CookieOptions, RateLimitConfig, LockVaultPlugin, LockVaultHooks, MiddlewareOptions,
} from './types/index.js';
export { AuthErrorCode } from './types/index.js';

// ─── Key-Value Store ─────────────────────────────────────────────────────
export { createMemoryKeyValueStore } from './store/index.js';

// ─── Errors ──────────────────────────────────────────────────────────────
export {
  LockVaultError, TokenExpiredError, TokenInvalidError, TokenRevokedError,
  RefreshTokenReuseError, SessionError, TOTPError, OAuthError,
  ConfigurationError, EmailError,
} from './utils/errors.js';

// ─── Rate Limiting ───────────────────────────────────────────────────────
export { createRateLimiter, RateLimitError } from './ratelimit/index.js';
export type { RateLimiterConfig, RateLimiter } from './ratelimit/index.js';

// ─── Email (optional — requires `nodemailer`) ───────────────────────────
// Full-featured SMTP mailer with themed auth templates AND general-purpose mailing:
//   import { createEmailManager } from 'lockvault/email';
export type {
  EmailConfig, SMTPConfig, SendEmailOptions, SendTemplateEmailOptions,
  SendCustomTemplateOptions, SendNamedTemplateOptions, SendBulkOptions,
  BulkEmailResult, EmailResult, TemplateDefinition, TemplateSource,
  CustomRenderFn, LoginEmailVars, ForgotPasswordEmailVars, AlertEmailVars,
  WelcomeEmailVars, VerificationEmailVars, MagicLinkEmailVars,
  EmailTemplateCategory, LoginTheme, ForgotPasswordTheme, AlertTheme,
} from './email/types.js';

// ─── Utilities ───────────────────────────────────────────────────────────
export { hashPassword, verifyPassword, generateId, generateUUID, generateBackupCodes, generateTokenFingerprint, sanitizeIpAddress, generatePKCE, generateCSRFToken } from './utils/crypto.js';

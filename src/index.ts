// ─── Core ────────────────────────────────────────────────────────────────
export { LockVault } from './core/index.js';

// ─── Modules ─────────────────────────────────────────────────────────────
export { JWTManager } from './jwt/index.js';
export { SessionManager } from './session/index.js';
export { TOTPManager } from './totp/index.js';
export { OAuthManager } from './oauth/index.js';

// ─── Adapters ────────────────────────────────────────────────────────────
export { MemoryAdapter } from './adapters/memory/index.js';
// Database-specific adapters are exported from sub-paths:
//   import { PostgresAdapter } from 'lockvault/adapters/postgres';
//   import { MongoDBAdapter }  from 'lockvault/adapters/mongodb';
//   import { RedisAdapter }    from 'lockvault/adapters/redis';

// ─── Middleware ───────────────────────────────────────────────────────────
// Framework-specific middleware is exported from sub-paths:
//   import { authenticate, authorize } from 'lockvault/middleware/express';
//   import { lockVaultPlugin }         from 'lockvault/middleware/fastify';

// ─── Types ───────────────────────────────────────────────────────────────
export type {
  Algorithm,
  TokenPayload,
  AccessTokenPayload,
  RefreshTokenPayload,
  TokenPair,
  DecodedToken,
  Session,
  DeviceInfo,
  AuthUser,
  OAuthLink,
  TOTPConfig,
  TOTPSetupResult,
  OAuthProviderConfig,
  OAuthUserProfile,
  OAuthTokenResponse,
  OAuthProviderPreset,
  DatabaseAdapter,
  KeyValueStore,
  LockVaultConfig,
  CookieOptions,
  RateLimitConfig,
  LockVaultPlugin,
  LockVaultHooks,
  MiddlewareOptions,
} from './types/index.js';

export { AuthErrorCode } from './types/index.js';

// ─── Key-Value Store ─────────────────────────────────────────────────────
export { MemoryKeyValueStore } from './store/index.js';

// ─── Errors ──────────────────────────────────────────────────────────────
export {
  LockVaultError,
  TokenExpiredError,
  TokenInvalidError,
  TokenRevokedError,
  RefreshTokenReuseError,
  SessionError,
  TOTPError,
  OAuthError,
  ConfigurationError,
} from './utils/errors.js';

// ─── Rate Limiting ───────────────────────────────────────────────────────
export { RateLimiter, RateLimitError } from './ratelimit/index.js';
export type { RateLimiterConfig } from './ratelimit/index.js';

// ─── Utilities ───────────────────────────────────────────────────────────
export {
  hashPassword,
  verifyPassword,
  generateId,
  generateUUID,
  generateBackupCodes,
} from './utils/crypto.js';

# LockVault

Authentication toolkit for Node.js. One package for JWT tokens, sessions, two-factor auth, OAuth logins, and database storage — with zero runtime dependencies.

```
npm install lockvault
```

## Why LockVault?

Most auth setups need you to wire together 5+ packages (jsonwebtoken, express-session, speakeasy, passport, etc.) and get the security details right yourself. LockVault gives you all of it in one import, with safe defaults already configured.

```typescript
import { LockVault, MemoryAdapter } from 'lockvault';

const auth = new LockVault({
  jwt: { accessTokenSecret: process.env.JWT_SECRET! },
  adapter: new MemoryAdapter(), // swap for Postgres/MongoDB/Redis in production
});

await auth.initialize();

// Log a user in — returns JWT tokens + a session
const { tokens, session } = await auth.login('user-123');

// Verify a token on any request
const payload = await auth.jwt.verifyAccessToken(tokens.accessToken);
console.log(payload.sub); // 'user-123'

// Refresh when the access token expires
const newTokens = await auth.refresh(tokens.refreshToken);

// Log out (revokes the token and session)
await auth.logout(tokens.accessToken);
```

That's the basic flow. Everything below goes deeper.

---

## Table of Contents

- [Installation](#installation)
- [Core Concepts](#core-concepts)
- [Configuration Reference](#configuration-reference)
- [JWT Tokens](#jwt-tokens)
- [Sessions](#sessions)
- [TOTP / Two-Factor Auth](#totp--two-factor-auth)
- [OAuth / Social Login](#oauth--social-login)
- [Database Adapters](#database-adapters)
- [Express Middleware](#express-middleware)
- [Fastify Middleware](#fastify-middleware)
- [Rate Limiting](#rate-limiting)
- [Key-Value Store](#key-value-store)
- [Plugin System](#plugin-system)
- [Utility Functions](#utility-functions)
- [Error Handling](#error-handling)
- [Security Checklist](#security-checklist)
- [API Reference](#api-reference)
- [License](#license)

---

## Installation

```bash
npm install lockvault
```

LockVault has **zero runtime dependencies**. It uses only Node.js built-in `crypto`. You'll also install a database driver depending on which adapter you use:

```bash
npm install pg        # if using PostgreSQL
npm install mongodb   # if using MongoDB
npm install ioredis   # if using Redis
```

Requires **Node.js 18+**.

---

## Core Concepts

LockVault has four main pieces. You can use them all together through the `LockVault` class, or import any piece individually.

| Module | What it does |
|--------|-------------|
| **JWTManager** | Signs, verifies, refreshes, and revokes JWT tokens |
| **SessionManager** | Tracks login sessions per user and device |
| **TOTPManager** | Generates and verifies 2FA codes (Google Authenticator, etc.) |
| **OAuthManager** | Handles Google, GitHub, Facebook, Apple, and Microsoft login flows |

All four are connected through a **DatabaseAdapter** — an interface that tells LockVault where to store sessions, token families, TOTP secrets, and OAuth links. You pick the database; LockVault handles the logic.

---

## Configuration Reference

Here's every option available. Only `jwt.accessTokenSecret` and `adapter` are required for HS256 setups.

```typescript
import { LockVault, MemoryAdapter } from 'lockvault';
import type { LockVaultConfig } from 'lockvault';

const config: LockVaultConfig = {

  // ── JWT Settings (required) ──────────────────────────────────────────
  jwt: {
    algorithm: 'HS256',              // 'HS256' | 'RS256' | 'ES256' | 'ES384' | 'ES512' | 'EdDSA'
    accessTokenSecret: '...',        // min 32 chars for HS256 (not needed for asymmetric)
    refreshTokenSecret: '...',       // optional — defaults to accessTokenSecret
    accessTokenTTL: 900,             // seconds (default: 15 minutes)
    refreshTokenTTL: 604800,         // seconds (default: 7 days)
    issuer: 'my-app',               // optional — validated on verify if set
    audience: 'my-api',             // optional — validated on verify if set
    privateKey: '...',              // PEM string — required for RS256/ES256/ES384/ES512/EdDSA
    publicKey: '...',               // PEM string — required for RS256/ES256/ES384/ES512/EdDSA
  },

  // ── Session Settings ─────────────────────────────────────────────────
  session: {
    enabled: true,                   // default: true
    maxPerUser: 10,                  // max concurrent sessions per user
    inactivityTimeout: 7200,         // seconds — revoke after 2h of no activity
  },

  // ── Refresh Token Security ───────────────────────────────────────────
  refreshToken: {
    rotation: true,                  // new refresh token on every refresh (default: true)
    reuseDetection: true,            // detect stolen tokens (default: true)
    familyRevocationOnReuse: true,   // revoke ALL tokens if theft detected (default: true)
    encryption: {                    // optional — encrypt refresh tokens with AES-256-GCM
      enabled: true,
      key: '...',                    // 64-char hex string (= 32 bytes)
    },
  },

  // ── TOTP / 2FA ───────────────────────────────────────────────────────
  totp: {
    issuer: 'MyApp',                 // shows in authenticator apps
    algorithm: 'SHA1',               // 'SHA1' | 'SHA256' | 'SHA512'
    digits: 6,                       // code length
    period: 30,                      // seconds per code
    window: 1,                       // accept ±1 time step
  },

  // ── OAuth ────────────────────────────────────────────────────────────
  oauth: {
    providers: {},                   // configured via registerPreset/registerProvider
    stateStore: myRedisKvStore,      // optional — for multi-instance deployments
  },

  // ── Key-Value Store ──────────────────────────────────────────────────
  kvStore: myRedisKvStore,           // optional — for TOTP replay protection in multi-instance

  // ── Database Adapter (required) ──────────────────────────────────────
  adapter: new MemoryAdapter(),

  // ── Plugins ──────────────────────────────────────────────────────────
  plugins: [],
};

const auth = new LockVault(config);
await auth.initialize();
```

---

## JWT Tokens

### Supported Algorithms

| Algorithm | Type | Use Case |
|-----------|------|----------|
| `HS256` | Symmetric (shared secret) | Simple setups, single-service apps |
| `RS256` | RSA (key pair) | Microservices where verifiers don't need the signing key |
| `ES256` | ECDSA P-256 (key pair) | Smaller signatures, modern standard |
| `ES384` | ECDSA P-384 (key pair) | Higher security ECDSA |
| `ES512` | ECDSA P-521 (key pair) | Maximum ECDSA security |
| `EdDSA` | Ed25519 (key pair) | Fastest, smallest signatures, recommended for new projects |

### Using EdDSA (Ed25519) — Recommended

```typescript
import { generateKeyPairSync } from 'node:crypto';

// Generate a key pair (do this once, store the PEM strings in env vars)
const { privateKey, publicKey } = generateKeyPairSync('ed25519', {
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  publicKeyEncoding: { type: 'spki', format: 'pem' },
});

const auth = new LockVault({
  jwt: {
    algorithm: 'EdDSA',
    accessTokenSecret: '',       // not used for asymmetric algorithms
    privateKey,                  // signs tokens
    publicKey,                   // verifies tokens (safe to share)
  },
  adapter: new MemoryAdapter(),
});
```

### Using ES256 (ECDSA)

```typescript
const { privateKey, publicKey } = generateKeyPairSync('ec', {
  namedCurve: 'prime256v1',
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  publicKeyEncoding: { type: 'spki', format: 'pem' },
});

const auth = new LockVault({
  jwt: { algorithm: 'ES256', accessTokenSecret: '', privateKey, publicKey },
  adapter: new MemoryAdapter(),
});
```

### Token Claims

Every token includes these standard claims automatically:

| Claim | Meaning |
|-------|---------|
| `sub` | User ID |
| `iat` | Issued at (unix timestamp) |
| `nbf` | Not valid before (unix timestamp) |
| `exp` | Expires at (unix timestamp) |
| `jti` | Unique token ID (used for revocation) |
| `type` | `'access'` or `'refresh'` |
| `iss` | Issuer (if configured) |
| `aud` | Audience (if configured) |

You can add your own custom claims during login:

```typescript
const { tokens } = await auth.login('user-123', {
  customClaims: { roles: ['admin'], orgId: 'org-456' },
});

// Later, when verifying:
const payload = await auth.jwt.verifyAccessToken(tokens.accessToken);
console.log(payload.roles); // ['admin']
```

### Refresh Token Rotation

When a client refreshes, the old refresh token is invalidated and a new one is issued. If an attacker tries to reuse a stolen refresh token, LockVault detects it and revokes the entire token family — logging out all sessions for that user.

```typescript
// Normal flow:
const newTokens = await auth.refresh(tokens.refreshToken);
// ✓ Returns new access + refresh tokens

// Attacker replays the old refresh token:
await auth.refresh(tokens.refreshToken);
// ✗ Throws RefreshTokenReuseError — entire family revoked
```

### Key Rotation

Rotate your signing keys without invalidating existing tokens:

```typescript
auth.rotateJWTKeys('new-secret-at-least-32-characters-long!');
// New tokens use the new key
// Old tokens still verify against the previous key (up to 3 old keys kept)
```

---

## Sessions

Sessions track where a user is logged in and from which device. They work alongside JWT tokens — the session ID is embedded in the token's `sid` claim.

```typescript
// Get all active sessions for a user
const sessions = await auth.sessions.getUserSessions('user-123');

// Each session contains:
// { id, userId, deviceInfo, ipAddress, createdAt, expiresAt, lastActiveAt }

// Log in with device info
const { tokens, session } = await auth.login('user-123', {
  deviceInfo: { userAgent: req.headers['user-agent'], deviceType: 'mobile' },
  ipAddress: req.ip,
});

// Revoke a specific session (e.g., "log out my phone")
await auth.sessions.revokeSession(session.id);

// Log out everywhere
await auth.logoutAll('user-123');
```

### Session Limits

If a user exceeds `maxPerUser` sessions (default: 10), the oldest session is automatically revoked to make room for the new one.

### Inactivity Timeout

If `inactivityTimeout` is set, sessions are automatically revoked when they haven't been used for that many seconds. The middleware updates `lastActiveAt` on every authenticated request.

---

## TOTP / Two-Factor Auth

LockVault implements RFC 6238 (TOTP) and RFC 4226 (HOTP). Compatible with Google Authenticator, Authy, 1Password, and any TOTP app.

### Setup Flow

```typescript
// Step 1: Generate a secret and otpauth URI
const setup = await auth.setupTOTP('user-123', 'user@example.com');
// Returns: { secret, uri, backupCodes }

// Step 2: Show the user a QR code (use any QR library)
import QRCode from 'qrcode';   // npm install qrcode
const qrDataUrl = await QRCode.toDataURL(setup.uri);
// Display qrDataUrl as an <img> for the user to scan

// Step 3: User scans QR, types the 6-digit code to confirm
await auth.confirmTOTP('user-123', setup.secret, userEnteredCode, setup.backupCodes);
// 2FA is now active for this user

// Step 4: On future logins, verify the code
await auth.verifyTOTP('user-123', code);

// Disable 2FA
await auth.disableTOTP('user-123');
```

### Backup Codes

When TOTP is set up, 10 backup codes are generated (format: `XXXX-XXXX-XXXX`, 48 bits of entropy each). Users can enter a backup code instead of a TOTP code if they lose access to their authenticator app. Each backup code can only be used once.

```typescript
const remaining = await auth.totp.getBackupCodesCount('user-123');
const newCodes = await auth.totp.regenerateBackupCodes('user-123');
```

### Built-in Protections

LockVault's TOTP implementation includes three layers of protection that most libraries leave for you to build yourself:

- **Rate limiting** — 5 attempts per minute per user. Prevents brute-forcing 6-digit codes.
- **Replay protection** — Each code can only be used once within its validity window. Prevents intercepted codes from being reused.
- **Timing-safe comparison** — Code verification runs in constant time regardless of which digits match. Prevents timing side-channel attacks.

---

## OAuth / Social Login

Built-in presets for Google, GitHub, Facebook, Apple, and Microsoft. You can also register any custom OAuth 2.0 provider.

### Register a Provider

```typescript
auth.registerOAuthPreset('google', {
  clientId: process.env.GOOGLE_CLIENT_ID!,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
  redirectUri: 'https://myapp.com/auth/google/callback',
});

auth.registerOAuthPreset('github', {
  clientId: process.env.GITHUB_CLIENT_ID!,
  clientSecret: process.env.GITHUB_CLIENT_SECRET!,
  redirectUri: 'https://myapp.com/auth/github/callback',
});
```

### OAuth Flow

```typescript
// 1. Redirect the user to the provider's login page
app.get('/auth/google', async (req, res) => {
  const url = await auth.getOAuthAuthorizationUrl('google');
  res.redirect(url);
});

// 2. Handle the callback after the user logs in
app.get('/auth/google/callback', async (req, res) => {
  const { profile, tokens } = await auth.handleOAuthCallback(
    'google',
    req.query.code as string,
    req.query.state as string,
  );

  // profile = { id, email, name, avatar, raw }
  let userId = await auth.oauth.findUserByOAuth('google', profile.id);
  if (!userId) {
    userId = createUserInYourDB(profile);
    await auth.oauth.linkAccount(userId, 'google', profile, tokens);
  }

  const { tokens: authTokens } = await auth.login(userId);
  res.json(authTokens);
});
```

### Custom OAuth Provider

```typescript
auth.registerOAuthProvider('gitlab', {
  clientId: '...',
  clientSecret: '...',
  redirectUri: 'https://myapp.com/auth/gitlab/callback',
  authorizationUrl: 'https://gitlab.com/oauth/authorize',
  tokenUrl: 'https://gitlab.com/oauth/token',
  userInfoUrl: 'https://gitlab.com/api/v4/user',
  scopes: ['read_user'],
  mapProfile: (data) => ({
    id: String(data.id),
    email: String(data.email ?? ''),
    name: String(data.name ?? ''),
    avatar: String(data.avatar_url ?? ''),
    raw: data,
  }),
});
```

---

## Database Adapters

### PostgreSQL

```typescript
import { Pool } from 'pg';
import { PostgresAdapter } from 'lockvault/adapters/postgres';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const adapter = new PostgresAdapter(pool, { tablePrefix: 'auth_' });

const auth = new LockVault({ jwt: { ... }, adapter });
await auth.initialize(); // creates tables and indexes automatically
```

### MongoDB

```typescript
import { MongoClient } from 'mongodb';
import { MongoDBAdapter } from 'lockvault/adapters/mongodb';

const client = new MongoClient(process.env.MONGO_URL!);
const db = client.db('myapp');
const adapter = new MongoDBAdapter(db, { collectionPrefix: 'auth_' });
```

### Redis

```typescript
import Redis from 'ioredis';
import { RedisAdapter } from 'lockvault/adapters/redis';

const redis = new Redis(process.env.REDIS_URL);
const adapter = new RedisAdapter(redis, { prefix: 'auth:' });
// Sessions and revoked tokens auto-expire via Redis TTL
```

### In-Memory (for development and testing)

```typescript
import { MemoryAdapter } from 'lockvault';
const adapter = new MemoryAdapter();
```

### Custom Adapter

Implement the `DatabaseAdapter` interface. The `MemoryAdapter` source at `src/adapters/memory/index.ts` is a complete reference implementation.

```typescript
import type { DatabaseAdapter } from 'lockvault';

class MyAdapter implements DatabaseAdapter {
  async createSession(session) { /* ... */ }
  async getSession(id) { /* ... */ }
  async getSessionsByUser(userId) { /* ... */ }
  // ... see DatabaseAdapter interface for all required methods
}
```

---

## Express Middleware

```typescript
import { authenticate, authorize, csrfProtection, setAuthCookies, clearAuthCookies } from 'lockvault/middleware/express';

// Create the middleware
const authMiddleware = authenticate({
  jwtManager: auth.jwt,
  sessionManager: auth.sessions,  // optional — validates session too
});

// Protect a route
app.get('/api/me', authMiddleware, (req, res) => {
  res.json({ user: req.lockvault!.user });
});

// Role-based access
app.delete('/api/users/:id', authMiddleware, authorize('admin'), (req, res) => {
  // Only users with { roles: ['admin'] } in their token reach here
});

// Set auth cookies after login (httpOnly, secure, sameSite: lax)
app.post('/auth/login', async (req, res) => {
  const { tokens } = await auth.login(userId);
  setAuthCookies(res, tokens);
  res.json({ success: true });
});
```

---

## Fastify Middleware

```typescript
import { lockVaultPlugin, fastifyAuthorize } from 'lockvault/middleware/fastify';

await app.register(lockVaultPlugin, {
  jwtManager: auth.jwt,
  sessionManager: auth.sessions,
  publicRoutes: ['/auth/login', '/auth/register', '/health'],
});

// Every non-public route is now protected automatically

app.get('/api/admin', {
  preHandler: [fastifyAuthorize('admin')],
}, async (req) => {
  return { user: req.lockvault!.user };
});
```

---

## Rate Limiting

LockVault includes a sliding-window rate limiter. It's already used internally for TOTP, but you can use it for login endpoints, API routes, or anything else:

```typescript
import { RateLimiter, RateLimitError } from 'lockvault';

const loginLimiter = new RateLimiter({
  windowMs: 60_000,      // 1 minute window
  maxAttempts: 5,         // max 5 attempts per window
});

app.post('/auth/login', async (req, res) => {
  try {
    await loginLimiter.consume(req.ip);  // throws if over limit
    // ... do login ...
    loginLimiter.reset(req.ip);          // reset on success
  } catch (err) {
    if (err instanceof RateLimitError) {
      return res.status(429).json({
        error: err.message,
        retryAfterMs: err.retryAfterMs,
      });
    }
    throw err;
  }
});
```

---

## Key-Value Store

LockVault uses a `KeyValueStore` interface for ephemeral data (OAuth state, TOTP replay tracking). An in-memory store works out of the box. For **multi-instance deployments**, provide a shared store:

```typescript
import type { KeyValueStore } from 'lockvault';

// Example: Redis-backed store
class RedisKeyValueStore implements KeyValueStore {
  constructor(private redis: Redis) {}

  async get(key: string) { return this.redis.get(key); }
  async set(key: string, value: string, ttlMs?: number) {
    if (ttlMs) await this.redis.set(key, value, 'PX', ttlMs);
    else await this.redis.set(key, value);
  }
  async delete(key: string) { return (await this.redis.del(key)) > 0; }
}

const kvStore = new RedisKeyValueStore(redis);

const auth = new LockVault({
  jwt: { ... },
  adapter: postgresAdapter,
  kvStore,                        // TOTP replay protection across instances
  oauth: { providers: {}, stateStore: kvStore },  // OAuth state across instances
});
```

---

## Plugin System

Plugins let you hook into every step of the auth lifecycle:

```typescript
import type { LockVaultPlugin } from 'lockvault';

const auditPlugin: LockVaultPlugin = {
  name: 'audit-log',
  hooks: {
    afterTokenCreate: async (tokenPair) => {
      console.log('Token created:', tokenPair.accessTokenExpiresAt);
    },
    onReuseDetected: async (family, userId) => {
      await alertSecurityTeam(`Possible token theft for user ${userId}`);
    },
    onError: async (error, context) => {
      await logToSentry(error, { context });
    },
  },
};

const auth = new LockVault({ ...config, plugins: [auditPlugin] });
```

### Available Hooks

| Hook | When it fires |
|------|--------------|
| `beforeTokenCreate` | Before the JWT payload is signed |
| `afterTokenCreate` | After both tokens are created |
| `beforeTokenVerify` | Before signature verification |
| `afterTokenVerify` | After successful verification |
| `beforeSessionCreate` | Before session is saved |
| `afterSessionCreate` | After session is saved |
| `onTokenRevoked` | When a token is revoked |
| `onReuseDetected` | When refresh token reuse is detected |
| `onError` | On any auth error |

---

## Utility Functions

Standalone functions — no LockVault instance needed:

```typescript
import { hashPassword, verifyPassword, generateId, generateUUID, generateBackupCodes } from 'lockvault';

// Password hashing (scrypt, N=16384, r=8, p=1)
const hash = await hashPassword('my-password');
const isValid = await verifyPassword('my-password', hash);  // true

// Random IDs
const id = generateId(32);     // 64-char hex string
const uuid = generateUUID();   // UUID v4

// Backup codes (48-bit entropy each)
const codes = generateBackupCodes(10);  // ['A1B2-C3D4-E5F6', ...]
```

---

## Error Handling

Every error thrown by LockVault extends `LockVaultError` with a machine-readable `code` and HTTP `statusCode`:

```typescript
import { LockVaultError, TokenExpiredError, RateLimitError } from 'lockvault';

try {
  await auth.jwt.verifyAccessToken(token);
} catch (err) {
  if (err instanceof TokenExpiredError) {
    // err.code === 'TOKEN_EXPIRED', err.statusCode === 401
  }
  if (err instanceof RateLimitError) {
    // err.code === 'RATE_LIMITED', err.statusCode === 429
    // err.retryAfterMs → milliseconds until retry is allowed
  }
  if (err instanceof LockVaultError) {
    res.status(err.statusCode).json({ error: err.message, code: err.code });
  }
}
```

### Error Codes

| Code | Status | Meaning |
|------|--------|---------|
| `TOKEN_EXPIRED` | 401 | Access token is past its `exp` time |
| `TOKEN_INVALID` | 401 | Bad signature, wrong algorithm, malformed, or failed iss/aud check |
| `TOKEN_REVOKED` | 401 | Token was explicitly revoked |
| `REFRESH_TOKEN_REUSE` | 401 | A used refresh token was replayed (possible theft) |
| `SESSION_EXPIRED` | 401 | Session past expiry or inactivity timeout |
| `SESSION_NOT_FOUND` | 401 | Session ID doesn't exist |
| `SESSION_REVOKED` | 401 | Session was revoked |
| `TOTP_INVALID` | 400 | Wrong code, wrong backup code, or code already used |
| `TOTP_NOT_ENABLED` | 400 | TOTP hasn't been set up for this user |
| `TOTP_ALREADY_ENABLED` | 400 | TOTP already active — call `disable` first |
| `RATE_LIMITED` | 429 | Too many attempts — retry after the specified delay |
| `OAUTH_ERROR` | 400 | OAuth flow failed |
| `CONFIGURATION_ERROR` | 500 | Invalid config at startup |

---

## Security Checklist

These are the defaults, but verify your setup covers them:

- [ ] **JWT secrets are 32+ characters** — LockVault rejects shorter secrets at startup
- [ ] **Refresh token rotation is on** — enabled by default, detects token theft
- [ ] **Access token TTL is short** — 15 minutes by default
- [ ] **HTTPS only** — cookie defaults are `secure: true`
- [ ] **Algorithm is enforced** — tokens with a different `alg` header are rejected
- [ ] **Issuer/audience validated** — set `issuer` and `audience` in config
- [ ] **Encrypted refresh tokens** for sensitive apps — set `refreshToken.encryption`
- [ ] **Cleanup is running** — call `auth.startCleanup()` to purge expired data
- [ ] **Key rotation plan** — use `auth.rotateJWTKeys()` periodically
- [ ] **Graceful shutdown** — call `auth.close()` when your server stops

---

## API Reference

### `LockVault`

| Method | Returns | Description |
|--------|---------|-------------|
| `initialize()` | `Promise<void>` | Create database tables / indexes |
| `login(userId, options?)` | `Promise<{ tokens, session }>` | Log in — creates tokens + session |
| `refresh(refreshToken, claims?)` | `Promise<TokenPair>` | Refresh with automatic rotation |
| `logout(accessToken)` | `Promise<void>` | Revoke token + session |
| `logoutAll(userId)` | `Promise<number>` | Revoke all sessions for a user |
| `setupTOTP(userId, email?)` | `Promise<TOTPSetupResult>` | Generate TOTP setup |
| `confirmTOTP(userId, secret, code, backupCodes)` | `Promise<boolean>` | Confirm 2FA setup |
| `verifyTOTP(userId, code)` | `Promise<boolean>` | Verify a TOTP or backup code |
| `disableTOTP(userId)` | `Promise<void>` | Remove TOTP for a user |
| `registerOAuthPreset(preset, config)` | `void` | Register Google/GitHub/etc. |
| `registerOAuthProvider(name, config)` | `void` | Register a custom OAuth provider |
| `getOAuthAuthorizationUrl(provider)` | `Promise<string>` | Get the redirect URL |
| `handleOAuthCallback(provider, code, state)` | `Promise<{ profile, tokens }>` | Exchange code for profile |
| `rotateJWTKeys(newSecret)` | `void` | Rotate signing keys |
| `startCleanup(intervalMs?)` | `void` | Start automatic cleanup |
| `close()` | `Promise<void>` | Stop timers and close adapter |

### Sub-Modules

| Property | Type | Access |
|----------|------|--------|
| `auth.jwt` | `JWTManager` | Direct token operations |
| `auth.sessions` | `SessionManager` | Direct session operations |
| `auth.totp` | `TOTPManager` | Direct TOTP operations |
| `auth.oauth` | `OAuthManager` | Direct OAuth operations |
| `auth.adapter` | `DatabaseAdapter` | Direct database access |

---

## License

MIT

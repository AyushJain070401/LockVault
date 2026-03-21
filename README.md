# LockVault

[![CI](https://github.com/AyushJain070401/LockVault/actions/workflows/ci.yml/badge.svg)](https://github.com/AyushJain070401/LockVault/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/lockvault)](https://www.npmjs.com/package/lockvault)
[![Node](https://img.shields.io/node/v/lockvault)](https://www.npmjs.com/package/lockvault)
[![License](https://img.shields.io/npm/l/lockvault)](./LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)]()

**Production-grade authentication for Node.js.** JWT tokens, sessions, TOTP/2FA, OAuth, email — one package, zero runtime dependencies, safe defaults.

```
npm install lockvault
```

### What you get

- **JWT** — HS256, RS256, ES256, ES384, ES512, EdDSA. Refresh token rotation with reuse detection. Key rotation with grace period. Optional AES-256-GCM encryption.
- **Sessions** — Multi-device tracking, inactivity + absolute timeouts, automatic cleanup.
- **TOTP/2FA** — Google Authenticator compatible. Rate-limited verification, replay protection, backup codes.
- **OAuth** — Google, GitHub, Facebook, Apple, Microsoft. PKCE built in. Bring your own providers.
- **Email** — SMTP with themed templates (login alerts, password reset, etc.). Pluggable engines (Handlebars, EJS, MJML).
- **Database adapters** — Memory (dev), PostgreSQL, MongoDB, Redis. Or write your own with a single interface.
- **Middleware** — Express and Fastify out of the box. CSRF protection, security headers, cookie helpers.
- **Plugin system** — Lifecycle hooks for logging, auditing, custom claims injection.

### How it compares

| | LockVault | jsonwebtoken + express-session + speakeasy + passport | Better Auth | Auth.js |
|---|---|---|---|---|
| Runtime deps | **0** | 15+ | 5+ | 10+ |
| JWT + Sessions + TOTP + OAuth | **All in one** | Manual wiring | Yes | Partial |
| Database adapters | Postgres, MongoDB, Redis, Memory | DIY | ORM-based | ORM-based |
| Framework lock-in | None (Express/Fastify optional) | Express | None | Next.js / SvelteKit |
| Zero-config security defaults | ✓ | ✗ | ✓ | ✓ |
| Custom JWT algorithms (EdDSA, ES512) | ✓ | Limited | ✗ | ✗ |

```
npm install lockvault
```

## Quick Start

Most auth setups need you to wire together 5+ packages and get the security details right yourself. LockVault gives you all of it in one import, with safe defaults already configured.

```typescript
import { createLockVault, createMemoryAdapter } from 'lockvault';

const auth = createLockVault({
  jwt: { accessTokenSecret: process.env.JWT_SECRET! },
  adapter: createMemoryAdapter(), // swap for Postgres/MongoDB/Redis in production
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
- [Email / SMTP (Optional)](#email--smtp-optional)
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

LockVault has **zero runtime dependencies**. It uses only Node.js built-in `crypto`. Database drivers and email are optional — install only what you need:

```bash
npm install pg          # if using PostgreSQL
npm install mongodb     # if using MongoDB
npm install ioredis     # if using Redis
npm install nodemailer  # if using the email module (optional)
```

Requires **Node.js 18+**.

---

## Core Concepts

LockVault has four main pieces. You can use them all together through the `createLockVault()` factory, or import any piece individually.

| Module | What it does |
|--------|-------------|
| **JWTManager** | Signs, verifies, refreshes, and revokes JWT tokens |
| **SessionManager** | Tracks login sessions per user and device |
| **TOTPManager** | Generates and verifies 2FA codes (Google Authenticator, etc.) |
| **OAuthManager** | Handles Google, GitHub, Facebook, Apple, and Microsoft login flows |
| **EmailManager** | Optional SMTP email with themed templates and general-purpose mailing |

All four are connected through a **DatabaseAdapter** — an interface that tells LockVault where to store sessions, token families, TOTP secrets, and OAuth links. You pick the database; LockVault handles the logic. The **EmailManager** is a standalone module that works independently — it doesn't require a database adapter and can be used even without the core `createLockVault()` setup.

---

## Configuration Reference

Here's every option available. Only `jwt.accessTokenSecret` and `adapter` are required for HS256 setups.

```typescript
import { createLockVault, createMemoryAdapter } from 'lockvault';
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
  adapter: createMemoryAdapter(),

  // ── Plugins ──────────────────────────────────────────────────────────
  plugins: [],
};

const auth = createLockVault(config);
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

const auth = createLockVault({
  jwt: {
    algorithm: 'EdDSA',
    accessTokenSecret: '',       // not used for asymmetric algorithms
    privateKey,                  // signs tokens
    publicKey,                   // verifies tokens (safe to share)
  },
  adapter: createMemoryAdapter(),
});
```

### Using ES256 (ECDSA)

```typescript
const { privateKey, publicKey } = generateKeyPairSync('ec', {
  namedCurve: 'prime256v1',
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  publicKeyEncoding: { type: 'spki', format: 'pem' },
});

const auth = createLockVault({
  jwt: { algorithm: 'ES256', accessTokenSecret: '', privateKey, publicKey },
  adapter: createMemoryAdapter(),
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
import { createPostgresAdapter } from 'lockvault/adapters/postgres';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const adapter = createPostgresAdapter(pool, { tablePrefix: 'auth_' });

const auth = createLockVault({ jwt: { ... }, adapter });
await auth.initialize(); // creates tables and indexes automatically
```

### MongoDB

```typescript
import { MongoClient } from 'mongodb';
import { createMongoDBAdapter } from 'lockvault/adapters/mongodb';

const client = new MongoClient(process.env.MONGO_URL!);
const db = client.db('myapp');
const adapter = createMongoDBAdapter(db, { collectionPrefix: 'auth_' });
```

### Redis

```typescript
import Redis from 'ioredis';
import { createRedisAdapter } from 'lockvault/adapters/redis';

const redis = new Redis(process.env.REDIS_URL);
const adapter = createRedisAdapter(redis, { prefix: 'auth:' });
// Sessions and revoked tokens auto-expire via Redis TTL
```

### In-Memory (for development and testing)

```typescript
import { createMemoryAdapter } from 'lockvault';
const adapter = createMemoryAdapter();
```

### Custom Adapter

Implement the `DatabaseAdapter` interface. The `MemoryAdapter` source at `src/adapters/memory/index.ts` is a complete reference implementation.

```typescript
import type { DatabaseAdapter } from 'lockvault';

function createMyAdapter(): DatabaseAdapter {
  return {
    async createSession(session) { /* ... */ return session; },
    async getSession(id) { /* ... */ return null; },
    async getSessionsByUser(userId) { /* ... */ return []; },
    // ... see DatabaseAdapter interface for all required methods
  };
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
import { createRateLimiter, RateLimitError } from 'lockvault';

const loginLimiter = createRateLimiter({
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
function createRedisKeyValueStore(redis: Redis): KeyValueStore {
  return {
    async get(key) { return redis.get(key); },
    async set(key, value, ttlMs?) {
      if (ttlMs) await redis.set(key, value, 'PX', ttlMs);
      else await redis.set(key, value);
    },
    async delete(key) { return (await redis.del(key)) > 0; },
  };
}

const kvStore = createRedisKeyValueStore(redis);

const auth = createLockVault({
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

const auth = createLockVault({ ...config, plugins: [auditPlugin] });
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

## Email / SMTP (Optional)

LockVault includes a full-featured email module with themed templates for auth flows **and** general-purpose mailing. Email is **entirely optional** — LockVault works perfectly without it. If you never import from `lockvault/email`, nodemailer is never loaded and there's zero impact on your bundle.

**Install nodemailer only if you need email:**

```bash
npm install nodemailer
npm install -D @types/nodemailer  # TypeScript users
```

### Quick Setup

```typescript
import { createEmailManager } from 'lockvault/email';

const mailer = createEmailManager({
  smtp: {
    host: 'smtp.gmail.com',
    port: 587,
    auth: { user: 'you@gmail.com', pass: 'app-password' },
    from: '"My App" <you@gmail.com>',
  },
  defaults: { appName: 'My App', supportUrl: 'https://myapp.com/support' },
});
```

### General-Purpose Mailing

Use LockVault as a normal mailer — plain text, HTML, attachments, CC/BCC, priority headers:

```typescript
// Plain text
await mailer.sendMail({ to: 'user@example.com', subject: 'Hello', text: 'Just checking in.' });

// HTML with attachments
await mailer.sendMail({
  to: ['alice@example.com', 'bob@example.com'],
  subject: 'Monthly Report',
  html: '<h1>Report</h1><p>See attachment.</p>',
  attachments: [{ filename: 'report.pdf', path: './report.pdf' }],
  priority: 'high',
});

// CC, BCC, custom from, headers
await mailer.sendMail({
  to: 'user@example.com',
  cc: ['manager@example.com'],
  from: '"Finance" <finance@myapp.com>',  // override default from
  subject: 'Payment Confirmation',
  html: '<p>Your payment of $299 has been received.</p>',
  headers: { 'X-Transaction-ID': 'txn_abc' },
});
```

### Inline Templates

Pass HTML with `{{variable}}` interpolation — no registration needed:

```typescript
await mailer.sendCustom({
  to: 'user@example.com',
  subject: 'Order #{{orderId}} Confirmed',
  html: `
    <p>Hi {{name}}, your order #{{orderId}} is confirmed.</p>
    {{#if trackingUrl}}<a href="{{trackingUrl}}">Track shipment</a>{{/if}}
    {{#each items}}<p>• {{name}} — {{price}}</p>{{/each}}
  `,
  variables: {
    name: 'Ayush',
    orderId: 'ORD-123',
    trackingUrl: 'https://track.example.com/ORD-123',
    items: [{ name: 'Widget', price: '$29.99' }],
  },
});
```

The template engine supports `{{var}}`, `{{{rawVar}}}`, `{{#if var}}...{{/if}}`, `{{#unless var}}...{{/unless}}`, `{{#each items}}...{{/each}}`, and `{{nested.path}}` dot-notation.

### Built-In Auth Themes

9 production-ready email templates across 3 categories, each with 3 visual themes:

| Category | Themes | Convenience Method |
|---|---|---|
| Login Notification | `minimal`, `corporate`, `vibrant` | `sendLoginNotification()` |
| Forgot Password | `clean`, `secure`, `friendly` | `sendForgotPassword()` |
| Security Alert | `standard`, `urgent`, `subtle` | `sendAlert()` |

```typescript
await mailer.sendForgotPassword('user@example.com', {
  resetUrl: 'https://app.com/reset?token=abc',
  expiresIn: '15 minutes',
  theme: 'friendly',  // or 'clean', 'secure'
});

await mailer.sendLoginNotification('user@example.com', {
  loginTime: new Date().toLocaleString(),
  ipAddress: '192.168.1.42',
  deviceInfo: 'Chrome on macOS',
  theme: 'vibrant',
});

await mailer.sendAlert('admin@example.com', {
  alertTitle: 'Failed Login Attempts',
  alertMessage: '15 failed attempts from IP 10.0.0.1.',
  severity: 'critical',
  theme: 'urgent',
});
```

### Named Templates

Register templates once, send by name. Three source types — inline HTML, file-based, or a custom render function:

```typescript
// Inline HTML
mailer.registerNamedTemplate('order-shipped', {
  source: { type: 'html', content: '<p>Hi {{name}}, order #{{orderId}} shipped!</p>' },
  defaultSubject: 'Order #{{orderId}} Shipped',
});

// From a file on disk
mailer.registerNamedTemplate('welcome', {
  source: { type: 'file', path: './templates/welcome.html' },
  defaultSubject: 'Welcome to {{appName}}!',
});

// Custom render function (Handlebars, EJS, MJML, React Email, etc.)
mailer.registerNamedTemplate('newsletter', {
  source: { type: 'render', fn: (vars) => ejs.render(myTemplate, vars) },
  defaultSubject: '{{appName}} Newsletter',
});

// Send by name
await mailer.sendWithTemplate({
  to: 'user@example.com',
  template: 'order-shipped',
  variables: { name: 'Ayush', orderId: 'ORD-789' },
});
```

### Custom Categories and Themes

Create your own template categories with multiple themes, or override built-in ones:

```typescript
mailer.registerCategory('invoice', 'simple');
mailer.registerTemplate('invoice', 'simple', simpleInvoiceHtml);
mailer.registerTemplate('invoice', 'detailed', detailedInvoiceHtml);
mailer.setDefaultTheme('invoice', 'simple');

// Override built-in templates if you want
mailer.registerTemplate('login', 'minimal', myCustomLoginHtml);

// Remove templates/categories you don't need
mailer.removeTemplate('alert', 'subtle');
mailer.removeCategory('invoice');
```

### Custom Rendering Engine

Plug in any template engine globally — Handlebars, EJS, MJML, React Email, or anything else:

```typescript
import Handlebars from 'handlebars';

const mailer = createEmailManager({
  smtp: { /* ... */ },
  customRenderer: (html, vars) => Handlebars.compile(html)(vars),
});
```

### Bulk Sending

Send the same template to many recipients with per-recipient variables and optional rate limiting:

```typescript
const result = await mailer.sendBulk({
  subject: 'Your monthly summary',
  html: '<p>Hi {{name}}, you had {{count}} logins.</p>',
  recipients: [
    { to: 'alice@example.com', variables: { name: 'Alice', count: 42 } },
    { to: 'bob@example.com', variables: { name: 'Bob', count: 7 } },
  ],
  delayMs: 100, // 100ms between sends
});
// result = { total: 2, sent: 2, failed: 0, results: [...] }
```

### Preview and Development

Render templates without sending — useful for dev servers and testing:

```typescript
// Preview a category+theme template
const html = mailer.preview('login', 'vibrant', { userName: 'Test', loginTime: 'now' });

// Preview a named template
const html2 = await mailer.previewNamedTemplate('order-shipped', { name: 'Test', orderId: 'DEMO' });

// Render inline template (no SMTP needed)
const html3 = mailer.renderInline('<p>Hi {{name}}</p>', { name: 'Ayush' });

// Verify SMTP connection
const ok = await mailer.verify();  // true or false

// List everything available
mailer.listCategories();        // ['login', 'forgot-password', 'alert', ...]
mailer.listThemes('login');     // ['minimal', 'corporate', 'vibrant']
mailer.listNamedTemplates();    // ['order-shipped', 'welcome', ...]
```

### `createEmailManager()` API Reference

| Method | Description |
|--------|-------------|
| `sendMail(options)` | Send raw email (plain text, HTML, attachments) |
| `send(options)` | Alias for `sendMail()` |
| `sendCustom(options)` | Send with inline HTML template + variables |
| `sendWithTemplate(options)` | Send using a registered named template |
| `sendTemplate(options)` | Send using a category + theme template |
| `sendLoginNotification(to, vars)` | Login alert with themed template |
| `sendForgotPassword(to, vars)` | Password reset with themed template |
| `sendAlert(to, vars)` | Security alert with themed template |
| `sendBulk(options)` | Batch send with per-recipient variables |
| `registerNamedTemplate(name, def)` | Register a named template |
| `registerTemplate(category, theme, html)` | Register/override a category template |
| `registerCategory(name, defaultTheme?)` | Create a new category |
| `preview(category, theme, vars)` | Render category template without sending |
| `previewNamedTemplate(name, vars)` | Render named template without sending |
| `renderInline(html, vars)` | Render inline template string |
| `verify()` | Test SMTP connection |
| `close()` | Close SMTP connection pool |

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
| `EMAIL_ERROR` | 500 | SMTP connection or email send failure |

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

### `createLockVault(config)`

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

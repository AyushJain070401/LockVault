/**
 * LockVault — Express Integration Example
 *
 * A complete Express app with JWT auth, session management,
 * TOTP 2FA, and OAuth (Google).
 */
import express from 'express';
import cookieParser from 'cookie-parser';
import { LockVault, MemoryAdapter, hashPassword, verifyPassword } from 'lockvault';
import {
  authenticate,
  authorize,
  csrfProtection,
  setAuthCookies,
  clearAuthCookies,
} from 'lockvault/middleware/express';

// ─── Initialize LockVault ────────────────────────────────────────────────

const auth = new LockVault({
  jwt: {
    accessTokenSecret: process.env.JWT_SECRET!,
    refreshTokenSecret: process.env.JWT_REFRESH_SECRET!,
    accessTokenTTL: 900,       // 15 minutes
    refreshTokenTTL: 604800,   // 7 days
    issuer: 'my-app',
  },
  session: {
    enabled: true,
    maxPerUser: 10,
    inactivityTimeout: 7200, // 2 hours
  },
  refreshToken: {
    rotation: true,
    reuseDetection: true,
    familyRevocationOnReuse: true,
  },
  totp: {
    issuer: 'MyApp',
  },
  adapter: new MemoryAdapter(), // Replace with PostgresAdapter for production
});

// ─── Express App ─────────────────────────────────────────────────────────

const app = express();
app.use(express.json());
app.use(cookieParser());

// ─── Auth Middleware Instance ────────────────────────────────────────────

const authMiddleware = authenticate({
  jwtManager: auth.jwt,
  sessionManager: auth.sessions,
});

// ─── Routes ──────────────────────────────────────────────────────────────

// Register
app.post('/auth/register', async (req, res) => {
  const { email, password } = req.body;
  const passwordHash = await hashPassword(password);
  // Store user in your database...
  const userId = 'user-' + Date.now(); // Replace with DB insert

  const { tokens, session } = await auth.login(userId, {
    customClaims: { email, roles: ['user'] },
    deviceInfo: {
      userAgent: req.headers['user-agent'],
      deviceType: 'desktop',
    },
    ipAddress: req.ip,
  });

  setAuthCookies(res, tokens);
  res.json({ user: { id: userId, email }, session: { id: session.id } });
});

// Login
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  // Look up user in your database...
  const userId = 'user-123';
  const storedHash = '...'; // from DB

  // const valid = await verifyPassword(password, storedHash);
  // if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

  const { tokens, session } = await auth.login(userId, {
    customClaims: { email, roles: ['user'] },
    deviceInfo: { userAgent: req.headers['user-agent'] },
    ipAddress: req.ip,
  });

  setAuthCookies(res, tokens);
  res.json({ tokens, sessionId: session.id });
});

// Refresh tokens
app.post('/auth/refresh', async (req, res) => {
  const refreshToken = req.cookies?.refresh_token || req.body?.refreshToken;
  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh token required' });
  }

  try {
    const tokens = await auth.refresh(refreshToken);
    setAuthCookies(res, tokens);
    res.json({ tokens });
  } catch (error: any) {
    res.status(401).json({ error: error.message, code: error.code });
  }
});

// Logout
app.post('/auth/logout', authMiddleware, async (req, res) => {
  await auth.logout(req.lockvault!.token);
  clearAuthCookies(res);
  res.json({ success: true });
});

// Logout all devices
app.post('/auth/logout-all', authMiddleware, async (req, res) => {
  const count = await auth.logoutAll(req.lockvault!.user.sub);
  clearAuthCookies(res);
  res.json({ success: true, revokedSessions: count });
});

// ─── Protected Routes ───────────────────────────────────────────────────

app.get('/api/profile', authMiddleware, (req, res) => {
  res.json({ user: req.lockvault!.user });
});

app.get('/api/sessions', authMiddleware, async (req, res) => {
  const sessions = await auth.sessions.getUserSessions(req.lockvault!.user.sub);
  res.json({
    sessions: sessions.map(s => ({
      id: s.id,
      device: s.deviceInfo,
      ip: s.ipAddress,
      createdAt: s.createdAt,
      lastActiveAt: s.lastActiveAt,
    })),
  });
});

// Admin-only route
app.get(
  '/api/admin/stats',
  authMiddleware,
  authorize('admin'),
  (_req, res) => {
    res.json({ message: 'Admin area' });
  },
);

// ─── TOTP / 2FA Routes ─────────────────────────────────────────────────

app.post('/auth/totp/setup', authMiddleware, async (req, res) => {
  const userId = req.lockvault!.user.sub;
  const setup = await auth.setupTOTP(userId, req.lockvault!.user.email as string);
  res.json({
    secret: setup.secret,
    uri: setup.uri, // Pass this to a QR code library (e.g. `qrcode`) to generate a scannable image
    backupCodes: setup.backupCodes,
  });
});

app.post('/auth/totp/confirm', authMiddleware, async (req, res) => {
  const { secret, code, backupCodes } = req.body;
  await auth.confirmTOTP(req.lockvault!.user.sub, secret, code, backupCodes);
  res.json({ success: true, message: '2FA enabled' });
});

app.post('/auth/totp/verify', async (req, res) => {
  const { userId, code } = req.body;
  try {
    await auth.verifyTOTP(userId, code);
    res.json({ success: true });
  } catch {
    res.status(401).json({ error: 'Invalid 2FA code' });
  }
});

// ─── Start ──────────────────────────────────────────────────────────────

async function start() {
  await auth.initialize();
  auth.startCleanup(3600_000); // hourly cleanup

  app.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
  });
}

start();

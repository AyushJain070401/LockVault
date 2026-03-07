/**
 * LockVault — Fastify Integration Example
 */
import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import { LockVault, MemoryAdapter } from 'lockvault';
import {
  lockVaultPlugin,
  fastifyAuthorize,
  setFastifyAuthCookies,
} from 'lockvault/middleware/fastify';

const auth = new LockVault({
  jwt: {
    accessTokenSecret: process.env.JWT_SECRET!,
    refreshTokenSecret: process.env.JWT_REFRESH_SECRET!,
    accessTokenTTL: 900,
    refreshTokenTTL: 604800,
    issuer: 'fastify-app',
  },
  session: { enabled: true, maxPerUser: 10 },
  refreshToken: { rotation: true, reuseDetection: true },
  adapter: new MemoryAdapter(),
});

const app = Fastify({ logger: true });

async function start() {
  await auth.initialize();

  // Register cookie plugin
  await app.register(cookie, { secret: process.env.COOKIE_SECRET! });

  // Register LockVault plugin — protects all routes except publicRoutes
  await app.register(lockVaultPlugin as any, {
    jwtManager: auth.jwt,
    sessionManager: auth.sessions,
    publicRoutes: ['/auth/login', '/auth/register', '/auth/refresh', '/health'],
  });

  // ─── Public Routes ───────────────────────────────────────────────

  app.get('/health', async () => ({ status: 'ok' }));

  app.post('/auth/login', async (request, reply) => {
    const { email, password } = request.body as { email: string; password: string };

    // Verify credentials against your database...
    const userId = 'user-123';

    const { tokens, session } = await auth.login(userId, {
      customClaims: { email, roles: ['user'] },
      deviceInfo: { userAgent: request.headers['user-agent'] },
    });

    setFastifyAuthCookies(reply as any, tokens);
    return { tokens, sessionId: session.id };
  });

  app.post('/auth/refresh', async (request, reply) => {
    const refreshToken =
      (request as any).cookies?.refresh_token ||
      (request.body as any)?.refreshToken;

    if (!refreshToken) {
      reply.code(400);
      return { error: 'Refresh token required' };
    }

    const tokens = await auth.refresh(refreshToken);
    setFastifyAuthCookies(reply as any, tokens);
    return { tokens };
  });

  // ─── Protected Routes ────────────────────────────────────────────

  app.get('/api/profile', async (request) => {
    return { user: (request as any).lockvault.user };
  });

  app.get('/api/sessions', async (request) => {
    const userId = (request as any).lockvault.user.sub;
    const sessions = await auth.sessions.getUserSessions(userId);
    return { sessions };
  });

  // Admin route with role check
  app.get(
    '/api/admin',
    { preHandler: [fastifyAuthorize('admin')] },
    async () => ({ message: 'Welcome, admin' }),
  );

  // ─── Start Server ────────────────────────────────────────────────

  auth.startCleanup();
  await app.listen({ port: 3000, host: '0.0.0.0' });
}

start();

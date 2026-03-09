import type { TokenPayload, Session, CookieOptions } from '../types/index.js';
import type { JWTManager } from '../jwt/index.js';
import type { SessionManager } from '../session/index.js';
import { LockVaultError } from '../utils/errors.js';

// ─── Fastify type shims ─────────────────────────────────────────────────

interface FastifyRequest {
  headers: Record<string, string | string[] | undefined>;
  cookies?: Record<string, string>;
  query?: Record<string, unknown>;
  lockvault?: {
    user: TokenPayload;
    session?: Session;
    token: string;
  };
  [key: string]: unknown;
}

interface FastifyReply {
  code(statusCode: number): FastifyReply;
  send(payload?: unknown): FastifyReply;
  setCookie(name: string, value: string, options?: Record<string, unknown>): FastifyReply;
  clearCookie(name: string, options?: Record<string, unknown>): FastifyReply;
}

interface FastifyInstance {
  decorateRequest(property: string, value: unknown): void;
  addHook(hook: string, handler: (...args: unknown[]) => Promise<void>): void;
}

type FastifyPluginCallback = (
  instance: FastifyInstance,
  opts: FastifyAuthPluginOptions,
  done: (err?: Error) => void,
) => void;

// ─── Plugin Options ─────────────────────────────────────────────────────

export interface FastifyAuthPluginOptions {
  jwtManager: JWTManager;
  sessionManager?: SessionManager;
  tokenExtractor?: (req: FastifyRequest) => string | null;
  protectedRoutes?: string[];
  publicRoutes?: string[];
}

// ─── Token Extraction ────────────────────────────────────────────────────

function extractToken(req: FastifyRequest): string | null {
  const authHeader = req.headers.authorization;
  if (typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7);
  }
  if (req.cookies?.access_token) {
    return req.cookies.access_token;
  }
  return null;
}

// ─── Fastify Plugin ─────────────────────────────────────────────────────

export const lockVaultPlugin: FastifyPluginCallback = (fastify, opts, done) => {
  const { jwtManager, sessionManager, tokenExtractor, publicRoutes = [] } = opts;
  const extract = tokenExtractor ?? extractToken;

  // Decorate request with lockvault property
  fastify.decorateRequest('lockvault', null);

  // Pre-handler hook for authentication
  fastify.addHook('onRequest', async (rawReq: unknown, rawReply: unknown) => {
    const req = rawReq as FastifyRequest;
    const reply = rawReply as FastifyReply;
    const url = (req as Record<string, unknown>).url as string;

    // Skip public routes
    if (publicRoutes.some(route => url.startsWith(route))) {
      return;
    }

    const token = extract(req);
    if (!token) {
      reply.code(401).send({ error: 'Authentication required' });
      return;
    }

    try {
      const payload = await jwtManager.verifyAccessToken(token);
      req.lockvault = { user: payload, token };

      if (sessionManager && payload.sid) {
        const session = await sessionManager.getSession(payload.sid as string);
        req.lockvault.session = session;
        await sessionManager.touchSession(session.id);
      }
    } catch (error) {
      if (error instanceof LockVaultError) {
        reply.code(error.statusCode).send({ error: error.message, code: error.code });
        return;
      }
      reply.code(401).send({ error: 'Authentication failed' });
    }
  });

  done();
};

/**
 * Fastify pre-handler for role-based authorization.
 */
export function fastifyAuthorize(...roles: string[]) {
  return async (rawReq: unknown, rawReply: unknown) => {
    const req = rawReq as FastifyRequest;
    const reply = rawReply as FastifyReply;

    if (!req.lockvault?.user) {
      reply.code(401).send({ error: 'Authentication required' });
      return;
    }

    const userRoles = (req.lockvault.user.roles ?? []) as string[];
    const hasRole = roles.some(role => userRoles.includes(role));

    if (!hasRole) {
      reply.code(403).send({ error: 'Insufficient permissions' });
    }
  };
}

/**
 * Set auth cookies on Fastify reply.
 */
export function setFastifyAuthCookies(
  reply: FastifyReply,
  tokens: { accessToken: string; refreshToken: string },
  options: CookieOptions = {},
): void {
  const defaults = {
    httpOnly: true,
    secure: true,
    sameSite: 'lax' as const,
    path: '/',
    ...options,
  };

  reply.setCookie('access_token', tokens.accessToken, {
    ...defaults,
    maxAge: (defaults.maxAge ?? 900) * 1000,
  });

  reply.setCookie('refresh_token', tokens.refreshToken, {
    ...defaults,
    maxAge: (defaults.maxAge ?? 604800) * 1000,
    path: '/auth/refresh',
  });
}

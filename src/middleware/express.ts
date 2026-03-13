import type { TokenPayload, Session, CookieOptions } from '../types/index.js';
import type { JWTManager } from '../jwt/index.js';
import type { SessionManager } from '../session/index.js';
import { LockVaultError } from '../utils/errors.js';
import { safeCompare, generateCSRFToken } from '../utils/crypto.js';

// ─── Type shims for Express (avoids hard dependency) ──────────────────────

interface ExpressRequest {
  headers: Record<string, string | string[] | undefined>;
  cookies?: Record<string, string>;
  body?: Record<string, unknown>;
  query?: Record<string, unknown>;
  ip?: string;
  lockvault?: {
    user: TokenPayload;
    session?: Session;
    token: string;
  };
  [key: string]: unknown;
}

interface ExpressResponse {
  status(code: number): ExpressResponse;
  json(body: unknown): void;
  cookie(name: string, value: string, options?: Record<string, unknown>): void;
  clearCookie(name: string, options?: Record<string, unknown>): void;
}

type NextFunction = (err?: unknown) => void;
type ExpressMiddleware = (req: ExpressRequest, res: ExpressResponse, next: NextFunction) => void;

// ─── Token Extraction ────────────────────────────────────────────────────

function extractToken(req: ExpressRequest): string | null {
  // 1. Authorization header (preferred)
  const authHeader = req.headers.authorization;
  if (typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7);
  }

  // 2. Cookie
  if (req.cookies?.access_token) {
    return req.cookies.access_token;
  }

  // NOTE: Query parameter token extraction has been removed for security.
  // Tokens in URLs are logged by proxies, browsers, and analytics tools.

  return null;
}

// ─── Middleware Factory ──────────────────────────────────────────────────

export interface ExpressAuthOptions {
  jwtManager: JWTManager;
  sessionManager?: SessionManager;
  tokenExtractor?: (req: ExpressRequest) => string | null;
  onError?: (error: LockVaultError, req: ExpressRequest, res: ExpressResponse) => void;
}

/**
 * Authentication middleware for Express.
 * Verifies the access token and optionally validates the session.
 */
export function authenticate(options: ExpressAuthOptions): ExpressMiddleware {
  const { jwtManager, sessionManager, tokenExtractor, onError } = options;
  const extract = tokenExtractor ?? extractToken;

  return async (req: ExpressRequest, res: ExpressResponse, next: NextFunction) => {
    try {
      const token = extract(req);
      if (!token) {
        const err = new LockVaultError('No token provided', 'TOKEN_INVALID' as never, 401);
        if (onError) return onError(err, req, res);
        return res.status(401).json({ error: 'Authentication required' });
      }

      const payload = await jwtManager.verifyAccessToken(token);

      req.lockvault = { user: payload, token };

      // Optionally validate session
      if (sessionManager && payload.sid) {
        const session = await sessionManager.getSession(payload.sid as string);
        req.lockvault.session = session;
        await sessionManager.touchSession(session.id);
      }

      next();
    } catch (error) {
      if (error instanceof LockVaultError) {
        if (onError) return onError(error, req, res);
        // Don't leak internal error details — use generic messages
        const safeMessage = error.statusCode === 401 ? 'Authentication failed' : error.message;
        return res.status(error.statusCode).json({ error: safeMessage, code: error.code });
      }
      next(error);
    }
  };
}

/**
 * Role-based authorization middleware.
 */
export function authorize(...roles: string[]): ExpressMiddleware {
  return (req: ExpressRequest, res: ExpressResponse, next: NextFunction) => {
    if (!req.lockvault?.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const userRoles = (req.lockvault.user.roles ?? []) as string[];
    const hasRole = roles.some(role => userRoles.includes(role));

    if (!hasRole) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    next();
  };
}

/**
 * CSRF protection middleware.
 * Validates that the CSRF token in the header matches the one in the cookie.
 */
export function csrfProtection(options: { cookieName?: string; headerName?: string } = {}): ExpressMiddleware {
  const cookieName = options.cookieName ?? 'csrf_token';
  const headerName = options.headerName ?? 'x-csrf-token';

  return (req: ExpressRequest, res: ExpressResponse, next: NextFunction) => {
    // Skip safe methods
    const method = (req as Record<string, unknown>).method as string;
    if (['GET', 'HEAD', 'OPTIONS'].includes(method)) {
      return next();
    }

    const cookieToken = req.cookies?.[cookieName];
    const headerToken = req.headers[headerName];

    if (!cookieToken || !headerToken || typeof headerToken !== 'string' || !safeCompare(cookieToken, headerToken)) {
      return res.status(403).json({ error: 'CSRF token mismatch' });
    }

    next();
  };
}

/**
 * Generate and set a CSRF token cookie on the response.
 * Call this on GET requests so the client can read the cookie
 * and send it back as a header on state-changing requests.
 */
export function setCSRFCookie(
  res: ExpressResponse,
  options: { cookieName?: string; secure?: boolean; sameSite?: string } = {},
): string {
  const token = generateCSRFToken();
  const cookieName = options.cookieName ?? 'csrf_token';
  res.cookie(cookieName, token, {
    httpOnly: false, // Client JS needs to read this
    secure: options.secure ?? true,
    sameSite: options.sameSite ?? 'lax',
    path: '/',
  });
  return token;
}

/**
 * Helper to set auth cookies on a response.
 */
export function setAuthCookies(
  res: ExpressResponse,
  tokens: { accessToken: string; refreshToken: string },
  options: CookieOptions = {},
): void {
  const defaults: CookieOptions = {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    path: '/',
    ...options,
  };

  res.cookie('access_token', tokens.accessToken, {
    ...defaults,
    maxAge: (defaults.maxAge ?? 900) * 1000,
  });

  res.cookie('refresh_token', tokens.refreshToken, {
    ...defaults,
    maxAge: (defaults.maxAge ?? 604800) * 1000,
    path: '/auth/refresh', // only sent to refresh endpoint
  });
}

/**
 * Helper to clear auth cookies.
 */
export function clearAuthCookies(res: ExpressResponse): void {
  res.clearCookie('access_token', { path: '/' });
  res.clearCookie('refresh_token', { path: '/auth/refresh' });
}

/**
 * Security headers middleware.
 * Sets recommended HTTP headers for auth-related responses.
 */
export function securityHeaders(): ExpressMiddleware {
  return (_req: ExpressRequest, res: ExpressResponse, next: NextFunction) => {
    const r = res as unknown as Record<string, Function>;
    if (r.setHeader) {
      r.setHeader('X-Content-Type-Options', 'nosniff');
      r.setHeader('X-Frame-Options', 'DENY');
      r.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
      r.setHeader('Pragma', 'no-cache');
    }
    next();
  };
}

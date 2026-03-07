import { o as TokenPayload, S as Session, C as CookieOptions } from '../index-BPNrRCYx.mjs';
import { J as JWTManager, S as SessionManager } from '../index-CQV8FdRX.mjs';
import { L as LockVaultError } from '../errors-BvUXMuaK.mjs';

interface ExpressRequest {
    headers: Record<string, string | string[] | undefined>;
    cookies?: Record<string, string>;
    body?: Record<string, unknown>;
    query?: Record<string, unknown>;
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
interface ExpressAuthOptions {
    jwtManager: JWTManager;
    sessionManager?: SessionManager;
    tokenExtractor?: (req: ExpressRequest) => string | null;
    onError?: (error: LockVaultError, req: ExpressRequest, res: ExpressResponse) => void;
}
/**
 * Authentication middleware for Express.
 * Verifies the access token and optionally validates the session.
 */
declare function authenticate(options: ExpressAuthOptions): ExpressMiddleware;
/**
 * Role-based authorization middleware.
 */
declare function authorize(...roles: string[]): ExpressMiddleware;
/**
 * CSRF protection middleware.
 * Validates that the CSRF token in the header matches the one in the cookie.
 */
declare function csrfProtection(options?: {
    cookieName?: string;
    headerName?: string;
}): ExpressMiddleware;
/**
 * Helper to set auth cookies on a response.
 */
declare function setAuthCookies(res: ExpressResponse, tokens: {
    accessToken: string;
    refreshToken: string;
}, options?: CookieOptions): void;
/**
 * Helper to clear auth cookies.
 */
declare function clearAuthCookies(res: ExpressResponse): void;

export { type ExpressAuthOptions, authenticate, authorize, clearAuthCookies, csrfProtection, setAuthCookies };

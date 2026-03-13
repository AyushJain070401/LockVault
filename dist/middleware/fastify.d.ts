import { o as TokenPayload, S as Session, C as CookieOptions } from '../index-BR3ae_bk.js';
import { J as JWTManager, S as SessionManager } from '../index-DHVNaTEZ.js';

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
    sent: boolean;
    setCookie(name: string, value: string, options?: Record<string, unknown>): FastifyReply;
    clearCookie(name: string, options?: Record<string, unknown>): FastifyReply;
}
interface FastifyInstance {
    decorateRequest(property: string, value: unknown): void;
    addHook(hook: string, handler: (...args: unknown[]) => Promise<void>): void;
}
type FastifyPluginCallback = (instance: FastifyInstance, opts: FastifyAuthPluginOptions, done: (err?: Error) => void) => void;
interface FastifyAuthPluginOptions {
    jwtManager: JWTManager;
    sessionManager?: SessionManager;
    tokenExtractor?: (req: FastifyRequest) => string | null;
    protectedRoutes?: string[];
    publicRoutes?: string[];
}
declare const lockVaultPlugin: FastifyPluginCallback;
/**
 * Fastify pre-handler for role-based authorization.
 */
declare function fastifyAuthorize(...roles: string[]): (rawReq: unknown, rawReply: unknown) => Promise<void>;
/**
 * Set auth cookies on Fastify reply.
 */
declare function setFastifyAuthCookies(reply: FastifyReply, tokens: {
    accessToken: string;
    refreshToken: string;
}, options?: CookieOptions): void;

export { type FastifyAuthPluginOptions, fastifyAuthorize, lockVaultPlugin, setFastifyAuthCookies };

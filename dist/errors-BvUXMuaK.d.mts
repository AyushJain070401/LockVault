import { i as AuthErrorCode } from './index-BPNrRCYx.mjs';

declare class LockVaultError extends Error {
    readonly code: AuthErrorCode;
    readonly statusCode: number;
    readonly details?: Record<string, unknown>;
    constructor(message: string, code: AuthErrorCode, statusCode?: number, details?: Record<string, unknown>);
    toJSON(): {
        name: string;
        message: string;
        code: AuthErrorCode;
        statusCode: number;
        details: Record<string, unknown> | undefined;
    };
}
declare class TokenExpiredError extends LockVaultError {
    constructor(message?: string);
}
declare class TokenInvalidError extends LockVaultError {
    constructor(message?: string);
}
declare class TokenRevokedError extends LockVaultError {
    constructor(message?: string);
}
declare class RefreshTokenReuseError extends LockVaultError {
    constructor(family: string);
}
declare class SessionError extends LockVaultError {
    constructor(message: string, code: AuthErrorCode);
}
declare class TOTPError extends LockVaultError {
    constructor(message: string, code: AuthErrorCode);
}
declare class OAuthError extends LockVaultError {
    constructor(message: string, details?: Record<string, unknown>);
}
declare class ConfigurationError extends LockVaultError {
    constructor(message: string);
}

export { ConfigurationError as C, LockVaultError as L, OAuthError as O, RefreshTokenReuseError as R, SessionError as S, TOTPError as T, TokenExpiredError as a, TokenInvalidError as b, TokenRevokedError as c };

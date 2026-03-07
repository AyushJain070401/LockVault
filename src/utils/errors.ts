import { AuthErrorCode } from '../types/index.js';

export class LockVaultError extends Error {
  public readonly code: AuthErrorCode;
  public readonly statusCode: number;
  public readonly details?: Record<string, unknown>;

  constructor(
    message: string,
    code: AuthErrorCode,
    statusCode: number = 401,
    details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = 'LockVaultError';
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
    Object.setPrototypeOf(this, LockVaultError.prototype);
  }

  toJSON() {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      statusCode: this.statusCode,
      details: this.details,
    };
  }
}

export class TokenExpiredError extends LockVaultError {
  constructor(message = 'Token has expired') {
    super(message, AuthErrorCode.TOKEN_EXPIRED, 401);
    this.name = 'TokenExpiredError';
  }
}

export class TokenInvalidError extends LockVaultError {
  constructor(message = 'Token is invalid') {
    super(message, AuthErrorCode.TOKEN_INVALID, 401);
    this.name = 'TokenInvalidError';
  }
}

export class TokenRevokedError extends LockVaultError {
  constructor(message = 'Token has been revoked') {
    super(message, AuthErrorCode.TOKEN_REVOKED, 401);
    this.name = 'TokenRevokedError';
  }
}

export class RefreshTokenReuseError extends LockVaultError {
  constructor(family: string) {
    super(
      'Refresh token reuse detected — all tokens in this family have been revoked',
      AuthErrorCode.REFRESH_TOKEN_REUSE,
      401,
      { family },
    );
    this.name = 'RefreshTokenReuseError';
  }
}

export class SessionError extends LockVaultError {
  constructor(message: string, code: AuthErrorCode) {
    super(message, code, 401);
    this.name = 'SessionError';
  }
}

export class TOTPError extends LockVaultError {
  constructor(message: string, code: AuthErrorCode) {
    super(message, code, 400);
    this.name = 'TOTPError';
  }
}

export class OAuthError extends LockVaultError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(message, AuthErrorCode.OAUTH_ERROR, 400, details);
    this.name = 'OAuthError';
  }
}

export class ConfigurationError extends LockVaultError {
  constructor(message: string) {
    super(message, AuthErrorCode.CONFIGURATION_ERROR, 500);
    this.name = 'ConfigurationError';
  }
}

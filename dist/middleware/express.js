'use strict';

var crypto = require('crypto');

// src/utils/errors.ts
var LockVaultError = class _LockVaultError extends Error {
  code;
  statusCode;
  details;
  constructor(message, code, statusCode = 401, details) {
    super(message);
    this.name = "LockVaultError";
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
    Object.setPrototypeOf(this, _LockVaultError.prototype);
  }
  toJSON() {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      statusCode: this.statusCode,
      details: this.details
    };
  }
};
function safeCompare(a, b) {
  const key = "lockvault-safe-compare";
  const hmacA = crypto.createHmac("sha256", key).update(a).digest();
  const hmacB = crypto.createHmac("sha256", key).update(b).digest();
  return crypto.timingSafeEqual(hmacA, hmacB) && a.length === b.length;
}

// src/middleware/express.ts
function extractToken(req) {
  const authHeader = req.headers.authorization;
  if (typeof authHeader === "string" && authHeader.startsWith("Bearer ")) {
    return authHeader.slice(7);
  }
  if (req.cookies?.access_token) {
    return req.cookies.access_token;
  }
  if (typeof req.query?.token === "string") {
    return req.query.token;
  }
  return null;
}
function authenticate(options) {
  const { jwtManager, sessionManager, tokenExtractor, onError } = options;
  const extract = tokenExtractor ?? extractToken;
  return async (req, res, next) => {
    try {
      const token = extract(req);
      if (!token) {
        const err = new LockVaultError("No token provided", "TOKEN_INVALID", 401);
        if (onError) return onError(err, req, res);
        return res.status(401).json({ error: "Authentication required" });
      }
      const payload = await jwtManager.verifyAccessToken(token);
      req.lockvault = { user: payload, token };
      if (sessionManager && payload.sid) {
        const session = await sessionManager.getSession(payload.sid);
        req.lockvault.session = session;
        await sessionManager.touchSession(session.id);
      }
      next();
    } catch (error) {
      if (error instanceof LockVaultError) {
        if (onError) return onError(error, req, res);
        return res.status(error.statusCode).json({ error: error.message, code: error.code });
      }
      next(error);
    }
  };
}
function authorize(...roles) {
  return (req, res, next) => {
    if (!req.lockvault?.user) {
      return res.status(401).json({ error: "Authentication required" });
    }
    const userRoles = req.lockvault.user.roles ?? [];
    const hasRole = roles.some((role) => userRoles.includes(role));
    if (!hasRole) {
      return res.status(403).json({ error: "Insufficient permissions" });
    }
    next();
  };
}
function csrfProtection(options = {}) {
  const cookieName = options.cookieName ?? "csrf_token";
  const headerName = options.headerName ?? "x-csrf-token";
  return (req, res, next) => {
    const method = req.method;
    if (["GET", "HEAD", "OPTIONS"].includes(method)) {
      return next();
    }
    const cookieToken = req.cookies?.[cookieName];
    const headerToken = req.headers[headerName];
    if (!cookieToken || !headerToken || typeof headerToken !== "string" || !safeCompare(cookieToken, headerToken)) {
      return res.status(403).json({ error: "CSRF token mismatch" });
    }
    next();
  };
}
function setAuthCookies(res, tokens, options = {}) {
  const defaults = {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    ...options
  };
  res.cookie("access_token", tokens.accessToken, {
    ...defaults,
    maxAge: (defaults.maxAge ?? 900) * 1e3
  });
  res.cookie("refresh_token", tokens.refreshToken, {
    ...defaults,
    maxAge: (defaults.maxAge ?? 604800) * 1e3,
    path: "/auth/refresh"
    // only sent to refresh endpoint
  });
}
function clearAuthCookies(res) {
  res.clearCookie("access_token", { path: "/" });
  res.clearCookie("refresh_token", { path: "/auth/refresh" });
}

exports.authenticate = authenticate;
exports.authorize = authorize;
exports.clearAuthCookies = clearAuthCookies;
exports.csrfProtection = csrfProtection;
exports.setAuthCookies = setAuthCookies;
//# sourceMappingURL=express.js.map
//# sourceMappingURL=express.js.map
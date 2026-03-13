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

// src/middleware/fastify.ts
function extractToken(req) {
  const authHeader = req.headers.authorization;
  if (typeof authHeader === "string" && authHeader.startsWith("Bearer ")) {
    return authHeader.slice(7);
  }
  if (req.cookies?.access_token) {
    return req.cookies.access_token;
  }
  return null;
}
var lockVaultPlugin = (fastify, opts, done) => {
  const { jwtManager, sessionManager, tokenExtractor, publicRoutes = [] } = opts;
  const extract = tokenExtractor ?? extractToken;
  fastify.decorateRequest("lockvault", null);
  fastify.addHook("onRequest", async (rawReq, rawReply) => {
    const req = rawReq;
    const reply = rawReply;
    const url = req.url;
    if (publicRoutes.some((route) => url.startsWith(route))) {
      return;
    }
    const token = extract(req);
    if (!token) {
      reply.code(401).send({ error: "Authentication required" });
      throw new Error("Authentication required");
    }
    try {
      const payload = await jwtManager.verifyAccessToken(token);
      req.lockvault = { user: payload, token };
      if (sessionManager && payload.sid) {
        const session = await sessionManager.getSession(payload.sid);
        req.lockvault.session = session;
        await sessionManager.touchSession(session.id);
      }
    } catch (error) {
      if (error instanceof LockVaultError) {
        reply.code(error.statusCode).send({ error: "Authentication failed", code: error.code });
      } else {
        reply.code(401).send({ error: "Authentication failed" });
      }
      throw error;
    }
  });
  done();
};
function fastifyAuthorize(...roles) {
  return async (rawReq, rawReply) => {
    const req = rawReq;
    const reply = rawReply;
    if (!req.lockvault?.user) {
      reply.code(401).send({ error: "Authentication required" });
      throw new Error("Authentication required");
    }
    const userRoles = req.lockvault.user.roles ?? [];
    const hasRole = roles.some((role) => userRoles.includes(role));
    if (!hasRole) {
      reply.code(403).send({ error: "Insufficient permissions" });
      throw new Error("Insufficient permissions");
    }
  };
}
function setFastifyAuthCookies(reply, tokens, options = {}) {
  const defaults = {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    ...options
  };
  reply.setCookie("access_token", tokens.accessToken, {
    ...defaults,
    maxAge: (defaults.maxAge ?? 900) * 1e3
  });
  reply.setCookie("refresh_token", tokens.refreshToken, {
    ...defaults,
    maxAge: (defaults.maxAge ?? 604800) * 1e3,
    path: "/auth/refresh"
  });
}

export { fastifyAuthorize, lockVaultPlugin, setFastifyAuthCookies };
//# sourceMappingURL=fastify.mjs.map
//# sourceMappingURL=fastify.mjs.map
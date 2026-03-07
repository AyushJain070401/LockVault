'use strict';

var crypto = require('crypto');

// src/jwt/index.ts

// src/types/index.ts
var AuthErrorCode = /* @__PURE__ */ ((AuthErrorCode2) => {
  AuthErrorCode2["TOKEN_EXPIRED"] = "TOKEN_EXPIRED";
  AuthErrorCode2["TOKEN_INVALID"] = "TOKEN_INVALID";
  AuthErrorCode2["TOKEN_REVOKED"] = "TOKEN_REVOKED";
  AuthErrorCode2["TOKEN_MALFORMED"] = "TOKEN_MALFORMED";
  AuthErrorCode2["REFRESH_TOKEN_REUSE"] = "REFRESH_TOKEN_REUSE";
  AuthErrorCode2["SESSION_EXPIRED"] = "SESSION_EXPIRED";
  AuthErrorCode2["SESSION_NOT_FOUND"] = "SESSION_NOT_FOUND";
  AuthErrorCode2["SESSION_REVOKED"] = "SESSION_REVOKED";
  AuthErrorCode2["MAX_SESSIONS_REACHED"] = "MAX_SESSIONS_REACHED";
  AuthErrorCode2["TOTP_INVALID"] = "TOTP_INVALID";
  AuthErrorCode2["TOTP_NOT_ENABLED"] = "TOTP_NOT_ENABLED";
  AuthErrorCode2["TOTP_ALREADY_ENABLED"] = "TOTP_ALREADY_ENABLED";
  AuthErrorCode2["BACKUP_CODE_INVALID"] = "BACKUP_CODE_INVALID";
  AuthErrorCode2["OAUTH_ERROR"] = "OAUTH_ERROR";
  AuthErrorCode2["OAUTH_STATE_MISMATCH"] = "OAUTH_STATE_MISMATCH";
  AuthErrorCode2["ADAPTER_ERROR"] = "ADAPTER_ERROR";
  AuthErrorCode2["CONFIGURATION_ERROR"] = "CONFIGURATION_ERROR";
  AuthErrorCode2["RATE_LIMITED"] = "RATE_LIMITED";
  AuthErrorCode2["ENCRYPTION_ERROR"] = "ENCRYPTION_ERROR";
  return AuthErrorCode2;
})(AuthErrorCode || {});

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
var TokenExpiredError = class extends LockVaultError {
  constructor(message = "Token has expired") {
    super(message, "TOKEN_EXPIRED" /* TOKEN_EXPIRED */, 401);
    this.name = "TokenExpiredError";
  }
};
var TokenInvalidError = class extends LockVaultError {
  constructor(message = "Token is invalid") {
    super(message, "TOKEN_INVALID" /* TOKEN_INVALID */, 401);
    this.name = "TokenInvalidError";
  }
};
var TokenRevokedError = class extends LockVaultError {
  constructor(message = "Token has been revoked") {
    super(message, "TOKEN_REVOKED" /* TOKEN_REVOKED */, 401);
    this.name = "TokenRevokedError";
  }
};
var RefreshTokenReuseError = class extends LockVaultError {
  constructor(family) {
    super(
      "Refresh token reuse detected \u2014 all tokens in this family have been revoked",
      "REFRESH_TOKEN_REUSE" /* REFRESH_TOKEN_REUSE */,
      401,
      { family }
    );
    this.name = "RefreshTokenReuseError";
  }
};
var SessionError = class extends LockVaultError {
  constructor(message, code) {
    super(message, code, 401);
    this.name = "SessionError";
  }
};
var TOTPError = class extends LockVaultError {
  constructor(message, code) {
    super(message, code, 400);
    this.name = "TOTPError";
  }
};
var OAuthError = class extends LockVaultError {
  constructor(message, details) {
    super(message, "OAUTH_ERROR" /* OAUTH_ERROR */, 400, details);
    this.name = "OAuthError";
  }
};
var ConfigurationError = class extends LockVaultError {
  constructor(message) {
    super(message, "CONFIGURATION_ERROR" /* CONFIGURATION_ERROR */, 500);
    this.name = "ConfigurationError";
  }
};

// src/utils/crypto.ts
function generateId(length = 32) {
  return crypto.randomBytes(length).toString("hex");
}
function generateUUID() {
  const bytes = crypto.randomBytes(16);
  bytes[6] = bytes[6] & 15 | 64;
  bytes[8] = bytes[8] & 63 | 128;
  const hex = bytes.toString("hex");
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32)
  ].join("-");
}
function safeCompare(a, b) {
  const key = "lockvault-safe-compare";
  const hmacA = crypto.createHmac("sha256", key).update(a).digest();
  const hmacB = crypto.createHmac("sha256", key).update(b).digest();
  return crypto.timingSafeEqual(hmacA, hmacB) && a.length === b.length;
}
function encrypt(plaintext, keyHex) {
  if (keyHex.length !== 64) {
    throw new ConfigurationError("Encryption key must be 32 bytes (64 hex characters)");
  }
  const key = Buffer.from(keyHex, "hex");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, encrypted]).toString("base64url");
}
function decrypt(ciphertext, keyHex) {
  if (keyHex.length !== 64) {
    throw new ConfigurationError("Encryption key must be 32 bytes (64 hex characters)");
  }
  try {
    const key = Buffer.from(keyHex, "hex");
    const data = Buffer.from(ciphertext, "base64url");
    const iv = data.subarray(0, 12);
    const authTag = data.subarray(12, 28);
    const encrypted = data.subarray(28);
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(authTag);
    return decipher.update(encrypted) + decipher.final("utf8");
  } catch {
    throw new LockVaultError("Failed to decrypt token", "ENCRYPTION_ERROR" /* ENCRYPTION_ERROR */, 401);
  }
}
async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const derived = await new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 }, (err, key) => {
      if (err) reject(err);
      else resolve(key);
    });
  });
  return `${salt}:${derived.toString("hex")}`;
}
async function verifyPassword(password, hash) {
  const [salt, key] = hash.split(":");
  if (!salt || !key) return false;
  const derived = await new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 }, (err, derivedKey) => {
      if (err) reject(err);
      else resolve(derivedKey);
    });
  });
  return safeCompare(derived.toString("hex"), key);
}
function generateBackupCodes(count = 10) {
  const codes = [];
  for (let i = 0; i < count; i++) {
    const code = crypto.randomBytes(6).toString("hex").toUpperCase();
    codes.push(`${code.slice(0, 4)}-${code.slice(4, 8)}-${code.slice(8, 12)}`);
  }
  return codes;
}
var BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32Encode(buffer) {
  let result = "";
  let bits = 0;
  let value = 0;
  for (const byte of buffer) {
    value = value << 8 | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      result += BASE32_CHARS[value >>> bits & 31];
    }
  }
  if (bits > 0) {
    result += BASE32_CHARS[value << 5 - bits & 31];
  }
  return result;
}
function base32Decode(encoded) {
  const cleaned = encoded.replace(/=+$/, "").toUpperCase();
  const bytes = [];
  let bits = 0;
  let value = 0;
  for (const char of cleaned) {
    const idx = BASE32_CHARS.indexOf(char);
    if (idx === -1) throw new Error(`Invalid base32 character: ${char}`);
    value = value << 5 | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push(value >>> bits & 255);
    }
  }
  return Buffer.from(bytes);
}

// src/jwt/index.ts
function base64UrlEncode(data) {
  const buf = typeof data === "string" ? Buffer.from(data) : data;
  return buf.toString("base64url");
}
function base64UrlDecode(str) {
  return Buffer.from(str, "base64url").toString("utf8");
}
var JWTManager = class _JWTManager {
  config;
  adapter;
  hooks;
  // Key rotation support
  previousSecrets = [];
  constructor(config, hooks = {}) {
    this.config = config;
    this.adapter = config.adapter;
    this.hooks = hooks;
    this.validateConfig();
  }
  static ASYMMETRIC_ALGS = /* @__PURE__ */ new Set(["RS256", "ES256", "ES384", "ES512", "EdDSA"]);
  validateConfig() {
    const { jwt } = this.config;
    const alg = jwt.algorithm ?? "HS256";
    if (_JWTManager.ASYMMETRIC_ALGS.has(alg)) {
      if (!jwt.privateKey || !jwt.publicKey) {
        throw new ConfigurationError(`privateKey and publicKey are required for ${alg}`);
      }
    } else {
      if (!jwt.accessTokenSecret) {
        throw new ConfigurationError(`accessTokenSecret is required for ${alg}`);
      }
      if (jwt.accessTokenSecret.length < 32) {
        throw new ConfigurationError(`accessTokenSecret must be at least 32 characters for ${alg}`);
      }
      if (jwt.refreshTokenSecret && jwt.refreshTokenSecret.length < 32) {
        throw new ConfigurationError(`refreshTokenSecret must be at least 32 characters for ${alg}`);
      }
    }
  }
  // ─── Token Creation ─────────────────────────────────────────────────────
  async createTokenPair(userId, customClaims = {}, sessionId) {
    const now = Math.floor(Date.now() / 1e3);
    const jwtConfig = this.config.jwt;
    const accessTTL = jwtConfig.accessTokenTTL ?? 900;
    const refreshTTL = jwtConfig.refreshTokenTTL ?? 604800;
    let claims = { ...customClaims };
    if (this.hooks.beforeTokenCreate) {
      claims = await this.hooks.beforeTokenCreate(claims);
    }
    const accessJti = generateUUID();
    const refreshJti = generateUUID();
    const family = generateUUID();
    const accessPayload = {
      sub: userId,
      iat: now,
      nbf: now,
      exp: now + accessTTL,
      jti: accessJti,
      type: "access",
      ...jwtConfig.issuer ? { iss: jwtConfig.issuer } : {},
      ...jwtConfig.audience ? { aud: jwtConfig.audience } : {},
      ...sessionId ? { sid: sessionId } : {},
      ...claims
    };
    const refreshPayload = {
      sub: userId,
      iat: now,
      nbf: now,
      exp: now + refreshTTL,
      jti: refreshJti,
      type: "refresh",
      family,
      generation: 0,
      ...jwtConfig.issuer ? { iss: jwtConfig.issuer } : {},
      ...sessionId ? { sid: sessionId } : {}
    };
    const accessToken = this.sign(accessPayload, jwtConfig.accessTokenSecret);
    let refreshToken = this.sign(
      refreshPayload,
      jwtConfig.refreshTokenSecret ?? jwtConfig.accessTokenSecret
    );
    const encConfig = this.config.refreshToken?.encryption;
    if (encConfig?.enabled) {
      refreshToken = encrypt(refreshToken, encConfig.key);
    }
    await this.adapter.storeRefreshTokenFamily(family, userId, 0);
    const tokenPair = {
      accessToken,
      refreshToken,
      accessTokenExpiresAt: new Date((now + accessTTL) * 1e3),
      refreshTokenExpiresAt: new Date((now + refreshTTL) * 1e3)
    };
    if (this.hooks.afterTokenCreate) {
      await this.hooks.afterTokenCreate(tokenPair);
    }
    return tokenPair;
  }
  // ─── Token Verification ─────────────────────────────────────────────────
  async verifyAccessToken(token) {
    let processedToken = token;
    if (this.hooks.beforeTokenVerify) {
      processedToken = await this.hooks.beforeTokenVerify(processedToken);
    }
    const payload = this.verify(processedToken, this.config.jwt.accessTokenSecret);
    if (payload.type !== "access") {
      throw new TokenInvalidError("Expected access token");
    }
    if (await this.adapter.isRevoked(payload.jti)) {
      throw new TokenRevokedError();
    }
    if (this.hooks.afterTokenVerify) {
      await this.hooks.afterTokenVerify(payload);
    }
    return payload;
  }
  async verifyRefreshToken(token) {
    let processedToken = token;
    const encConfig = this.config.refreshToken?.encryption;
    if (encConfig?.enabled) {
      processedToken = decrypt(processedToken, encConfig.key);
    }
    const secret = this.config.jwt.refreshTokenSecret ?? this.config.jwt.accessTokenSecret;
    const payload = this.verify(processedToken, secret);
    if (payload.type !== "refresh") {
      throw new TokenInvalidError("Expected refresh token");
    }
    return payload;
  }
  // ─── Token Refresh with Rotation ────────────────────────────────────────
  async refreshTokens(refreshToken, customClaims = {}) {
    const payload = await this.verifyRefreshToken(refreshToken);
    const { family, generation, sub: userId } = payload;
    const familyRecord = await this.adapter.getRefreshTokenFamily(family);
    if (!familyRecord) {
      throw new TokenInvalidError("Unknown refresh token family");
    }
    if (familyRecord.revoked) {
      throw new TokenRevokedError("Refresh token family has been revoked");
    }
    const reuseConfig = this.config.refreshToken;
    if (reuseConfig?.reuseDetection !== false && generation < familyRecord.generation) {
      if (reuseConfig?.familyRevocationOnReuse !== false) {
        await this.adapter.revokeRefreshTokenFamily(family);
        await this.adapter.deleteSessionsByUser(userId);
      }
      if (this.hooks.onReuseDetected) {
        await this.hooks.onReuseDetected(family, userId);
      }
      throw new RefreshTokenReuseError(family);
    }
    const now = Math.floor(Date.now() / 1e3);
    const jwtConfig = this.config.jwt;
    const accessTTL = jwtConfig.accessTokenTTL ?? 900;
    const refreshTTL = jwtConfig.refreshTokenTTL ?? 604800;
    let claims = { ...customClaims };
    if (this.hooks.beforeTokenCreate) {
      claims = await this.hooks.beforeTokenCreate(claims);
    }
    const newGeneration = await this.adapter.incrementRefreshTokenGeneration(family);
    const accessJti = generateUUID();
    const refreshJti = generateUUID();
    const accessPayload = {
      sub: userId,
      iat: now,
      nbf: now,
      exp: now + accessTTL,
      jti: accessJti,
      type: "access",
      ...jwtConfig.issuer ? { iss: jwtConfig.issuer } : {},
      ...jwtConfig.audience ? { aud: jwtConfig.audience } : {},
      ...payload.sid ? { sid: payload.sid } : {},
      ...claims
    };
    const refreshPayload = {
      sub: userId,
      iat: now,
      nbf: now,
      exp: now + refreshTTL,
      jti: refreshJti,
      type: "refresh",
      family,
      generation: newGeneration,
      ...jwtConfig.issuer ? { iss: jwtConfig.issuer } : {},
      ...payload.sid ? { sid: payload.sid } : {}
    };
    const newAccessToken = this.sign(accessPayload, jwtConfig.accessTokenSecret);
    let newRefreshToken = this.sign(
      refreshPayload,
      jwtConfig.refreshTokenSecret ?? jwtConfig.accessTokenSecret
    );
    const encConfig = this.config.refreshToken?.encryption;
    if (encConfig?.enabled) {
      newRefreshToken = encrypt(newRefreshToken, encConfig.key);
    }
    const tokenPair = {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      accessTokenExpiresAt: new Date((now + accessTTL) * 1e3),
      refreshTokenExpiresAt: new Date((now + refreshTTL) * 1e3)
    };
    if (this.hooks.afterTokenCreate) {
      await this.hooks.afterTokenCreate(tokenPair);
    }
    return tokenPair;
  }
  // ─── Token Revocation ───────────────────────────────────────────────────
  async revokeToken(token) {
    const parts = token.split(".");
    if (parts.length !== 3) {
      throw new TokenInvalidError("Cannot revoke: token is malformed");
    }
    const [headerB64, payloadB64, signature] = parts;
    const signingInput = `${headerB64}.${payloadB64}`;
    const algorithm = this.config.jwt.algorithm ?? "HS256";
    let header;
    try {
      header = JSON.parse(base64UrlDecode(headerB64));
    } catch {
      throw new TokenInvalidError("Cannot revoke: token is malformed");
    }
    if (header.alg !== algorithm) {
      throw new TokenInvalidError("Cannot revoke: algorithm mismatch");
    }
    let payload;
    try {
      payload = JSON.parse(base64UrlDecode(payloadB64));
    } catch {
      throw new TokenInvalidError("Cannot revoke: token is malformed");
    }
    const secret = payload.type === "refresh" ? this.config.jwt.refreshTokenSecret ?? this.config.jwt.accessTokenSecret : this.config.jwt.accessTokenSecret;
    const verified = this.verifySignature(algorithm, signingInput, signature, secret);
    if (!verified) {
      throw new TokenInvalidError("Cannot revoke: invalid signature");
    }
    await this.adapter.addToRevocationList(payload.jti, new Date(payload.exp * 1e3));
    if (payload.type === "refresh") {
      const refreshPayload = payload;
      await this.adapter.revokeRefreshTokenFamily(refreshPayload.family);
    }
    if (this.hooks.onTokenRevoked) {
      await this.hooks.onTokenRevoked(payload.jti);
    }
  }
  // ─── Key Rotation ──────────────────────────────────────────────────────
  rotateKeys(newSecret) {
    this.previousSecrets.push(this.config.jwt.accessTokenSecret);
    this.config.jwt.accessTokenSecret = newSecret;
    if (this.previousSecrets.length > 3) {
      this.previousSecrets.shift();
    }
  }
  // ─── Decode (without verification) ──────────────────────────────────────
  decode(token) {
    const parts = token.split(".");
    if (parts.length !== 3) {
      throw new TokenInvalidError("Token must have 3 parts");
    }
    try {
      const header = JSON.parse(base64UrlDecode(parts[0]));
      const payload = JSON.parse(base64UrlDecode(parts[1]));
      return { header, payload, signature: parts[2] };
    } catch {
      throw new TokenInvalidError("Failed to decode token");
    }
  }
  // ─── Low-level Sign / Verify ────────────────────────────────────────────
  sign(payload, secret) {
    const algorithm = this.config.jwt.algorithm ?? "HS256";
    const header = { alg: algorithm, typ: "JWT" };
    const headerB64 = base64UrlEncode(JSON.stringify(header));
    const payloadB64 = base64UrlEncode(JSON.stringify(payload));
    const signingInput = `${headerB64}.${payloadB64}`;
    const inputBuf = Buffer.from(signingInput);
    let signature;
    switch (algorithm) {
      case "HS256":
        signature = crypto.createHmac("sha256", secret).update(signingInput).digest("base64url");
        break;
      case "RS256": {
        const rsaSigner = crypto.createSign("RSA-SHA256");
        rsaSigner.update(signingInput);
        signature = rsaSigner.sign(this.config.jwt.privateKey, "base64url");
        break;
      }
      case "ES256": {
        const es256Signer = crypto.createSign("SHA256");
        es256Signer.update(signingInput);
        signature = es256Signer.sign(
          { key: this.config.jwt.privateKey, dsaEncoding: "ieee-p1363" },
          "base64url"
        );
        break;
      }
      case "ES384": {
        const es384Signer = crypto.createSign("SHA384");
        es384Signer.update(signingInput);
        signature = es384Signer.sign(
          { key: this.config.jwt.privateKey, dsaEncoding: "ieee-p1363" },
          "base64url"
        );
        break;
      }
      case "ES512": {
        const es512Signer = crypto.createSign("SHA512");
        es512Signer.update(signingInput);
        signature = es512Signer.sign(
          { key: this.config.jwt.privateKey, dsaEncoding: "ieee-p1363" },
          "base64url"
        );
        break;
      }
      case "EdDSA": {
        const edSig = crypto.sign(null, inputBuf, this.config.jwt.privateKey);
        signature = edSig.toString("base64url");
        break;
      }
      default:
        throw new ConfigurationError(`Unsupported algorithm: ${algorithm}`);
    }
    return `${signingInput}.${signature}`;
  }
  verify(token, secret) {
    const parts = token.split(".");
    if (parts.length !== 3) {
      throw new TokenInvalidError("Token must have 3 parts");
    }
    const [headerB64, payloadB64, signature] = parts;
    const signingInput = `${headerB64}.${payloadB64}`;
    const algorithm = this.config.jwt.algorithm ?? "HS256";
    let header;
    try {
      header = JSON.parse(base64UrlDecode(headerB64));
    } catch {
      throw new TokenInvalidError("Malformed token header");
    }
    if (header.alg !== algorithm) {
      throw new TokenInvalidError(
        `Algorithm mismatch: token uses "${header.alg}" but server requires "${algorithm}"`
      );
    }
    const verified = this.verifySignature(algorithm, signingInput, signature, secret);
    if (!verified) {
      throw new TokenInvalidError("Invalid signature");
    }
    const payload = JSON.parse(base64UrlDecode(payloadB64));
    const now = Math.floor(Date.now() / 1e3);
    if (payload.exp && payload.exp < now) {
      throw new TokenExpiredError();
    }
    if (payload.nbf && payload.nbf > now) {
      throw new TokenInvalidError("Token is not yet valid");
    }
    const expectedIssuer = this.config.jwt.issuer;
    if (expectedIssuer && payload.iss !== expectedIssuer) {
      throw new TokenInvalidError(
        `Issuer mismatch: expected "${expectedIssuer}" but got "${payload.iss}"`
      );
    }
    const expectedAudience = this.config.jwt.audience;
    if (expectedAudience) {
      const tokenAud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
      if (!tokenAud.includes(expectedAudience)) {
        throw new TokenInvalidError(
          `Audience mismatch: expected "${expectedAudience}"`
        );
      }
    }
    return payload;
  }
  // ─── Shared Signature Verification ──────────────────────────────────────
  verifySignature(algorithm, signingInput, signature, secret) {
    const sigBuf = Buffer.from(signature, "base64url");
    const inputBuf = Buffer.from(signingInput);
    switch (algorithm) {
      case "HS256": {
        const secrets = [secret, ...this.previousSecrets];
        for (const s of secrets) {
          const expected = crypto.createHmac("sha256", s).update(signingInput).digest("base64url");
          if (safeCompare(expected, signature)) return true;
        }
        return false;
      }
      case "RS256": {
        const rsaV = crypto.createVerify("RSA-SHA256");
        rsaV.update(signingInput);
        return rsaV.verify(this.config.jwt.publicKey, sigBuf);
      }
      case "ES256": {
        const es256V = crypto.createVerify("SHA256");
        es256V.update(signingInput);
        return es256V.verify({ key: this.config.jwt.publicKey, dsaEncoding: "ieee-p1363" }, sigBuf);
      }
      case "ES384": {
        const es384V = crypto.createVerify("SHA384");
        es384V.update(signingInput);
        return es384V.verify({ key: this.config.jwt.publicKey, dsaEncoding: "ieee-p1363" }, sigBuf);
      }
      case "ES512": {
        const es512V = crypto.createVerify("SHA512");
        es512V.update(signingInput);
        return es512V.verify({ key: this.config.jwt.publicKey, dsaEncoding: "ieee-p1363" }, sigBuf);
      }
      case "EdDSA":
        return crypto.verify(null, inputBuf, this.config.jwt.publicKey, sigBuf);
      default:
        return false;
    }
  }
};

// src/session/index.ts
var SessionManager = class {
  config;
  adapter;
  hooks;
  constructor(config, hooks = {}) {
    this.config = config;
    this.adapter = config.adapter;
    this.hooks = hooks;
  }
  /**
   * Create a new session for a user
   */
  async createSession(userId, refreshTokenFamily, options = {}) {
    const sessionConfig = this.config.session;
    if (sessionConfig?.maxPerUser) {
      const existing = await this.adapter.getSessionsByUser(userId);
      const activeSessions = existing.filter((s) => !s.isRevoked && s.expiresAt > /* @__PURE__ */ new Date());
      if (activeSessions.length >= sessionConfig.maxPerUser) {
        const oldest = activeSessions.sort(
          (a, b) => a.createdAt.getTime() - b.createdAt.getTime()
        )[0];
        if (oldest) {
          await this.adapter.deleteSession(oldest.id);
        }
      }
    }
    const ttl = options.expiresInSeconds ?? this.config.jwt.refreshTokenTTL ?? 604800;
    const now = /* @__PURE__ */ new Date();
    let sessionData = {
      id: generateUUID(),
      userId,
      refreshTokenFamily,
      deviceInfo: options.deviceInfo,
      ipAddress: options.ipAddress,
      createdAt: now,
      expiresAt: new Date(now.getTime() + ttl * 1e3),
      lastActiveAt: now,
      isRevoked: false,
      metadata: options.metadata
    };
    if (this.hooks.beforeSessionCreate) {
      sessionData = await this.hooks.beforeSessionCreate(sessionData);
    }
    const session = await this.adapter.createSession(sessionData);
    if (this.hooks.afterSessionCreate) {
      await this.hooks.afterSessionCreate(session);
    }
    return session;
  }
  /**
   * Get a session by ID
   */
  async getSession(sessionId) {
    const session = await this.adapter.getSession(sessionId);
    if (!session) {
      throw new SessionError("Session not found", "SESSION_NOT_FOUND" /* SESSION_NOT_FOUND */);
    }
    if (session.isRevoked) {
      throw new SessionError("Session has been revoked", "SESSION_REVOKED" /* SESSION_REVOKED */);
    }
    if (session.expiresAt < /* @__PURE__ */ new Date()) {
      throw new SessionError("Session has expired", "SESSION_EXPIRED" /* SESSION_EXPIRED */);
    }
    const inactivityTimeout = this.config.session?.inactivityTimeout;
    if (inactivityTimeout) {
      const inactiveMs = Date.now() - session.lastActiveAt.getTime();
      if (inactiveMs > inactivityTimeout * 1e3) {
        await this.revokeSession(sessionId);
        throw new SessionError("Session expired due to inactivity", "SESSION_EXPIRED" /* SESSION_EXPIRED */);
      }
    }
    return session;
  }
  /**
   * Touch/renew a session (update lastActiveAt)
   */
  async touchSession(sessionId) {
    return this.adapter.updateSession(sessionId, { lastActiveAt: /* @__PURE__ */ new Date() });
  }
  /**
   * Get all active sessions for a user
   */
  async getUserSessions(userId) {
    const sessions = await this.adapter.getSessionsByUser(userId);
    return sessions.filter((s) => !s.isRevoked && s.expiresAt > /* @__PURE__ */ new Date());
  }
  /**
   * Revoke a specific session
   */
  async revokeSession(sessionId) {
    const updated = await this.adapter.updateSession(sessionId, { isRevoked: true });
    return updated !== null;
  }
  /**
   * Revoke all sessions for a user
   */
  async revokeAllSessions(userId) {
    return this.adapter.deleteSessionsByUser(userId);
  }
  /**
   * Clean up expired sessions
   */
  async cleanup() {
    return this.adapter.deleteExpiredSessions();
  }
};

// src/ratelimit/index.ts
var RateLimitError = class _RateLimitError extends LockVaultError {
  retryAfterMs;
  constructor(identifier, retryAfterMs) {
    super(
      `Rate limit exceeded for "${identifier}". Retry after ${Math.ceil(retryAfterMs / 1e3)}s.`,
      "RATE_LIMITED" /* RATE_LIMITED */,
      429,
      { identifier, retryAfterMs }
    );
    this.name = "RateLimitError";
    this.retryAfterMs = retryAfterMs;
    Object.setPrototypeOf(this, _RateLimitError.prototype);
  }
};
var RateLimiter = class {
  config;
  store = /* @__PURE__ */ new Map();
  cleanupTimer;
  constructor(config = {}) {
    this.config = {
      windowMs: config.windowMs ?? 6e4,
      maxAttempts: config.maxAttempts ?? 5,
      onRateLimit: config.onRateLimit
    };
    this.cleanupTimer = setInterval(() => this.cleanup(), 3e5);
    if (this.cleanupTimer.unref) {
      this.cleanupTimer.unref();
    }
  }
  /**
   * Check and consume one attempt for the given identifier.
   * Throws `RateLimitError` if the limit is exceeded.
   */
  async consume(identifier) {
    const now = Date.now();
    const windowStart = now - this.config.windowMs;
    let entry = this.store.get(identifier);
    if (!entry) {
      entry = { timestamps: [] };
      this.store.set(identifier, entry);
    }
    entry.timestamps = entry.timestamps.filter((t) => t > windowStart);
    if (entry.timestamps.length >= this.config.maxAttempts) {
      const oldestInWindow = entry.timestamps[0];
      const retryAfterMs = oldestInWindow + this.config.windowMs - now;
      if (this.config.onRateLimit) {
        await this.config.onRateLimit(identifier);
      }
      throw new RateLimitError(identifier, retryAfterMs);
    }
    entry.timestamps.push(now);
  }
  /**
   * Reset the rate limit counter for a given identifier (e.g., after successful auth).
   */
  reset(identifier) {
    this.store.delete(identifier);
  }
  /**
   * Get remaining attempts for an identifier.
   */
  remaining(identifier) {
    const now = Date.now();
    const windowStart = now - this.config.windowMs;
    const entry = this.store.get(identifier);
    if (!entry) return this.config.maxAttempts;
    const recentAttempts = entry.timestamps.filter((t) => t > windowStart).length;
    return Math.max(0, this.config.maxAttempts - recentAttempts);
  }
  /**
   * Clean up expired entries to prevent memory leaks.
   */
  cleanup() {
    const now = Date.now();
    const windowStart = now - this.config.windowMs;
    for (const [key, entry] of this.store) {
      entry.timestamps = entry.timestamps.filter((t) => t > windowStart);
      if (entry.timestamps.length === 0) {
        this.store.delete(key);
      }
    }
  }
  /**
   * Stop the cleanup timer and clear internal state.
   */
  destroy() {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = void 0;
    }
    this.store.clear();
  }
};

// src/store/index.ts
var MemoryKeyValueStore = class {
  store = /* @__PURE__ */ new Map();
  cleanupTimer;
  maxEntries;
  constructor(options = {}) {
    this.maxEntries = options.maxEntries ?? 5e4;
    this.cleanupTimer = setInterval(() => this.cleanup(), options.cleanupIntervalMs ?? 6e4);
    if (this.cleanupTimer.unref) {
      this.cleanupTimer.unref();
    }
  }
  async get(key) {
    const entry = this.store.get(key);
    if (!entry) return null;
    if (entry.expiresAt && entry.expiresAt < Date.now()) {
      this.store.delete(key);
      return null;
    }
    return entry.value;
  }
  async set(key, value, ttlMs) {
    if (this.store.size >= this.maxEntries) {
      this.cleanup();
      if (this.store.size >= this.maxEntries) {
        const toRemove = this.store.size - this.maxEntries + 1;
        const keys = this.store.keys();
        for (let i = 0; i < toRemove; i++) {
          const k = keys.next().value;
          if (k) this.store.delete(k);
        }
      }
    }
    this.store.set(key, {
      value,
      expiresAt: ttlMs ? Date.now() + ttlMs : void 0
    });
  }
  async delete(key) {
    return this.store.delete(key);
  }
  cleanup() {
    const now = Date.now();
    for (const [key, entry] of this.store) {
      if (entry.expiresAt && entry.expiresAt < now) {
        this.store.delete(key);
      }
    }
  }
  destroy() {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = void 0;
    }
    this.store.clear();
  }
};

// src/totp/index.ts
var DEFAULT_TOTP_CONFIG = {
  issuer: "LockVault",
  algorithm: "SHA1",
  digits: 6,
  period: 30,
  window: 1
};
var TOTPManager = class {
  config;
  adapter;
  rateLimiter;
  replayStore;
  constructor(config = {}, adapter, kvStore) {
    this.config = { ...DEFAULT_TOTP_CONFIG, ...config };
    this.adapter = adapter;
    this.rateLimiter = new RateLimiter({ windowMs: 6e4, maxAttempts: 5 });
    this.replayStore = kvStore ?? new MemoryKeyValueStore({ maxEntries: 5e4 });
  }
  /**
   * Generate a new TOTP setup for a user (secret + otpauth URI + backup codes)
   */
  async setup(userId, userEmail) {
    const existing = await this.adapter.getTOTPSecret(userId);
    if (existing) {
      throw new TOTPError("TOTP is already enabled for this user", "TOTP_ALREADY_ENABLED" /* TOTP_ALREADY_ENABLED */);
    }
    const secret = this.generateSecret();
    const accountName = userEmail ?? userId;
    const uri = this.buildURI(secret, accountName);
    const backupCodes = generateBackupCodes(10);
    return { secret, uri, backupCodes };
  }
  /**
   * Confirm TOTP setup — verify a code, then persist the secret + backup codes
   */
  async confirmSetup(userId, secret, code, backupCodes) {
    if (!this.verifyCode(secret, code)) {
      throw new TOTPError("Invalid TOTP code", "TOTP_INVALID" /* TOTP_INVALID */);
    }
    await this.adapter.storeTOTPSecret(userId, secret);
    await this.adapter.storeBackupCodes(userId, backupCodes);
    return true;
  }
  /**
   * Verify a TOTP code for a user.
   * Rate-limited to 5 attempts per minute per user to prevent brute-force.
   */
  async verify(userId, code) {
    await this.rateLimiter.consume(`totp:${userId}`);
    const secret = await this.adapter.getTOTPSecret(userId);
    if (!secret) {
      throw new TOTPError("TOTP is not enabled for this user", "TOTP_NOT_ENABLED" /* TOTP_NOT_ENABLED */);
    }
    if (this.verifyCode(secret, code)) {
      const codeKey = `totp_used:${userId}:${code}`;
      const alreadyUsed = await this.replayStore.get(codeKey);
      if (alreadyUsed) {
        throw new TOTPError("TOTP code already used", "TOTP_INVALID" /* TOTP_INVALID */);
      }
      await this.replayStore.set(codeKey, "1", this.config.period * 2 * 1e3);
      this.rateLimiter.reset(`totp:${userId}`);
      return true;
    }
    const consumed = await this.adapter.consumeBackupCode(userId, code);
    if (consumed) {
      this.rateLimiter.reset(`totp:${userId}`);
      return true;
    }
    throw new TOTPError("Invalid TOTP or backup code", "TOTP_INVALID" /* TOTP_INVALID */);
  }
  /**
   * Disable TOTP for a user
   */
  async disable(userId) {
    const secret = await this.adapter.getTOTPSecret(userId);
    if (!secret) {
      throw new TOTPError("TOTP is not enabled for this user", "TOTP_NOT_ENABLED" /* TOTP_NOT_ENABLED */);
    }
    await this.adapter.removeTOTPSecret(userId);
  }
  /**
   * Get remaining backup codes count
   */
  async getBackupCodesCount(userId) {
    const codes = await this.adapter.getBackupCodes(userId);
    return codes.length;
  }
  /**
   * Regenerate backup codes
   */
  async regenerateBackupCodes(userId) {
    const secret = await this.adapter.getTOTPSecret(userId);
    if (!secret) {
      throw new TOTPError("TOTP is not enabled for this user", "TOTP_NOT_ENABLED" /* TOTP_NOT_ENABLED */);
    }
    const codes = generateBackupCodes(10);
    await this.adapter.storeBackupCodes(userId, codes);
    return codes;
  }
  // ─── Internal Helpers ────────────────────────────────────────────────────
  generateSecret(bytes = 20) {
    return base32Encode(crypto.randomBytes(bytes));
  }
  buildURI(secret, accountName) {
    const params = new URLSearchParams({
      secret,
      issuer: this.config.issuer,
      algorithm: this.config.algorithm,
      digits: String(this.config.digits),
      period: String(this.config.period)
    });
    const label = `${encodeURIComponent(this.config.issuer)}:${encodeURIComponent(accountName)}`;
    return `otpauth://totp/${label}?${params.toString()}`;
  }
  /**
   * Core TOTP code generation (RFC 6238)
   */
  generateCode(secret, time) {
    const now = time ?? Math.floor(Date.now() / 1e3);
    const counter = Math.floor(now / this.config.period);
    return this.hotpGenerate(secret, counter);
  }
  /**
   * Verify a TOTP code with time window tolerance.
   * Uses timing-safe comparison to prevent timing attacks.
   */
  verifyCode(secret, code) {
    const now = Math.floor(Date.now() / 1e3);
    const counter = Math.floor(now / this.config.period);
    let valid = false;
    for (let i = -this.config.window; i <= this.config.window; i++) {
      const expected = this.hotpGenerate(secret, counter + i);
      if (expected.length === code.length && safeCompare(expected, code)) {
        valid = true;
      }
    }
    return valid;
  }
  /**
   * HOTP generation (RFC 4226)
   */
  hotpGenerate(secret, counter) {
    const key = base32Decode(secret);
    const counterBuffer = Buffer.alloc(8);
    counterBuffer.writeBigUInt64BE(BigInt(counter));
    const algorithmMap = {
      SHA1: "sha1",
      SHA256: "sha256",
      SHA512: "sha512"
    };
    const hmac = crypto.createHmac(algorithmMap[this.config.algorithm], key);
    hmac.update(counterBuffer);
    const hash = hmac.digest();
    const offset = hash[hash.length - 1] & 15;
    const binary = (hash[offset] & 127) << 24 | (hash[offset + 1] & 255) << 16 | (hash[offset + 2] & 255) << 8 | hash[offset + 3] & 255;
    const otp = binary % Math.pow(10, this.config.digits);
    return otp.toString().padStart(this.config.digits, "0");
  }
};

// src/oauth/index.ts
var PROVIDER_PRESETS = {
  google: {
    authorizationUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    userInfoUrl: "https://www.googleapis.com/oauth2/v2/userinfo",
    scopes: ["openid", "email", "profile"],
    mapProfile: (p) => ({
      id: String(p.id),
      email: String(p.email ?? ""),
      name: String(p.name ?? ""),
      avatar: String(p.picture ?? ""),
      raw: p
    })
  },
  github: {
    authorizationUrl: "https://github.com/login/oauth/authorize",
    tokenUrl: "https://github.com/login/oauth/access_token",
    userInfoUrl: "https://api.github.com/user",
    scopes: ["read:user", "user:email"],
    mapProfile: (p) => ({
      id: String(p.id),
      email: String(p.email ?? ""),
      name: String(p.name ?? p.login ?? ""),
      avatar: String(p.avatar_url ?? ""),
      raw: p
    })
  },
  facebook: {
    authorizationUrl: "https://www.facebook.com/v18.0/dialog/oauth",
    tokenUrl: "https://graph.facebook.com/v18.0/oauth/access_token",
    userInfoUrl: "https://graph.facebook.com/me?fields=id,name,email,picture",
    scopes: ["email", "public_profile"],
    mapProfile: (p) => ({
      id: String(p.id),
      email: String(p.email ?? ""),
      name: String(p.name ?? ""),
      avatar: p.picture?.data?.url ?? "",
      raw: p
    })
  },
  apple: {
    authorizationUrl: "https://appleid.apple.com/auth/authorize",
    tokenUrl: "https://appleid.apple.com/auth/token",
    userInfoUrl: "",
    scopes: ["name", "email"],
    mapProfile: (p) => ({
      id: String(p.sub),
      email: String(p.email ?? ""),
      name: String(p.name ?? ""),
      raw: p
    })
  },
  microsoft: {
    authorizationUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    tokenUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    userInfoUrl: "https://graph.microsoft.com/v1.0/me",
    scopes: ["openid", "email", "profile"],
    mapProfile: (p) => ({
      id: String(p.id),
      email: String(p.mail ?? p.userPrincipalName ?? ""),
      name: String(p.displayName ?? ""),
      raw: p
    })
  }
};
var OAuthManager = class {
  providers = /* @__PURE__ */ new Map();
  adapter;
  stateStore;
  ownsStateStore;
  constructor(providerConfigs = {}, adapter, stateStore) {
    this.adapter = adapter;
    this.ownsStateStore = !stateStore;
    this.stateStore = stateStore ?? new MemoryKeyValueStore({ maxEntries: 1e4 });
    for (const [name, config] of Object.entries(providerConfigs)) {
      this.providers.set(name, config);
    }
  }
  /**
   * Clean up internal resources. Only destroys the state store if it was
   * created internally (not user-provided).
   */
  destroy() {
    if (this.ownsStateStore && "destroy" in this.stateStore) {
      this.stateStore.destroy();
    }
  }
  /**
   * Register a provider using a preset (Google, GitHub, etc.)
   */
  registerPreset(preset, config) {
    const base = PROVIDER_PRESETS[preset];
    this.providers.set(preset, {
      ...base,
      ...config,
      scopes: config.scopes ?? base.scopes
    });
  }
  /**
   * Register a custom OAuth provider
   */
  registerProvider(name, config) {
    this.providers.set(name, config);
  }
  /**
   * Generate the authorization URL for redirect
   */
  async getAuthorizationUrl(providerName, options = {}) {
    const provider = this.getProvider(providerName);
    const state = options.state ?? generateId(32);
    const stateData = JSON.stringify({
      provider: providerName,
      metadata: options.metadata
    });
    await this.stateStore.set(`oauth_state:${state}`, stateData, 6e5);
    const params = new URLSearchParams({
      client_id: provider.clientId,
      redirect_uri: provider.redirectUri,
      response_type: "code",
      state,
      ...provider.scopes?.length && { scope: provider.scopes.join(" ") }
    });
    return `${provider.authorizationUrl}?${params.toString()}`;
  }
  /**
   * Handle the OAuth callback — exchange code for tokens and fetch profile
   */
  async handleCallback(providerName, code, state) {
    const raw = await this.stateStore.get(`oauth_state:${state}`);
    if (!raw) {
      throw new OAuthError("Invalid or expired OAuth state", { provider: providerName });
    }
    const stateData = JSON.parse(raw);
    if (stateData.provider !== providerName) {
      throw new OAuthError("Invalid or expired OAuth state", { provider: providerName });
    }
    await this.stateStore.delete(`oauth_state:${state}`);
    const provider = this.getProvider(providerName);
    const tokens = await this.exchangeCode(provider, code);
    const profile = await this.fetchProfile(provider, tokens.access_token);
    return { profile, tokens };
  }
  /**
   * Link an OAuth account to an existing user
   */
  async linkAccount(userId, providerName, profile, tokens) {
    const link = {
      provider: providerName,
      providerUserId: profile.id,
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
      profile: profile.raw,
      linkedAt: /* @__PURE__ */ new Date()
    };
    await this.adapter.linkOAuthAccount(userId, link);
  }
  /**
   * Find an existing user by their OAuth identity
   */
  async findUserByOAuth(providerName, providerUserId) {
    return this.adapter.findUserByOAuth(providerName, providerUserId);
  }
  /**
   * Unlink an OAuth provider from a user
   */
  async unlinkAccount(userId, providerName) {
    return this.adapter.unlinkOAuthAccount(userId, providerName);
  }
  /**
   * Get all linked OAuth providers for a user
   */
  async getLinkedProviders(userId) {
    return this.adapter.getOAuthLinks(userId);
  }
  // ─── Internal ────────────────────────────────────────────────────────────
  getProvider(name) {
    const provider = this.providers.get(name);
    if (!provider) {
      throw new OAuthError(`OAuth provider '${name}' is not registered`);
    }
    return provider;
  }
  async exchangeCode(provider, code) {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: provider.redirectUri,
      client_id: provider.clientId,
      client_secret: provider.clientSecret
    });
    const response = await fetch(provider.tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json"
      },
      body: body.toString()
    });
    if (!response.ok) {
      const text = await response.text();
      throw new OAuthError(`Token exchange failed: ${response.status}`, { body: text });
    }
    return response.json();
  }
  async fetchProfile(provider, accessToken) {
    if (!provider.userInfoUrl) {
      throw new OAuthError("Provider does not support user info endpoint");
    }
    const response = await fetch(provider.userInfoUrl, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    if (!response.ok) {
      throw new OAuthError(`Failed to fetch user profile: ${response.status}`);
    }
    const data = await response.json();
    return provider.mapProfile(data);
  }
};

// src/core/index.ts
var LockVault = class _LockVault {
  jwt;
  sessions;
  totp;
  oauth;
  adapter;
  config;
  hooks;
  cleanupInterval;
  constructor(config) {
    this.config = this.validateAndNormalize(config);
    this.adapter = config.adapter;
    this.hooks = this.mergePluginHooks(config.plugins ?? []);
    this.jwt = new JWTManager(this.config, this.hooks);
    this.sessions = new SessionManager(this.config, this.hooks);
    this.totp = new TOTPManager(this.config.totp ?? {}, this.adapter, this.config.kvStore);
    this.oauth = new OAuthManager(this.config.oauth?.providers ?? {}, this.adapter, this.config.oauth?.stateStore);
  }
  // ─── Initialization ────────────────────────────────────────────────────
  async initialize() {
    if (this.adapter.initialize) {
      await this.adapter.initialize();
    }
  }
  /**
   * Start automatic cleanup of expired sessions and revocation entries.
   */
  startCleanup(intervalMs = 36e5) {
    this.stopCleanup();
    this.cleanupInterval = setInterval(async () => {
      try {
        await this.adapter.deleteExpiredSessions();
        await this.adapter.cleanupRevocationList();
      } catch (err) {
        if (this.hooks.onError) {
          await this.hooks.onError(err, "cleanup");
        }
      }
    }, intervalMs);
    if (this.cleanupInterval.unref) {
      this.cleanupInterval.unref();
    }
  }
  stopCleanup() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = void 0;
    }
  }
  // ─── High-Level Authentication API ──────────────────────────────────────
  /**
   * Authenticate a user and create a full token pair + session.
   */
  async login(userId, options = {}) {
    const session = await this.sessions.createSession(
      userId,
      generateId(16),
      // family tracking id
      {
        deviceInfo: options.deviceInfo,
        ipAddress: options.ipAddress,
        metadata: options.metadata
      }
    );
    const tokens = await this.jwt.createTokenPair(
      userId,
      { ...options.customClaims, sid: session.id },
      session.id
    );
    return { tokens, session };
  }
  /**
   * Refresh tokens with automatic rotation.
   */
  async refresh(refreshToken, customClaims) {
    return this.jwt.refreshTokens(refreshToken, customClaims);
  }
  /**
   * Logout — revoke the token and session.
   */
  async logout(accessToken) {
    try {
      const payload = await this.jwt.verifyAccessToken(accessToken);
      await this.jwt.revokeToken(accessToken);
      if (payload.sid) {
        await this.sessions.revokeSession(payload.sid);
      }
    } catch {
    }
  }
  /**
   * Logout from all devices — revoke all sessions.
   */
  async logoutAll(userId) {
    return this.sessions.revokeAllSessions(userId);
  }
  // ─── TOTP Convenience Methods ──────────────────────────────────────────
  async setupTOTP(userId, email) {
    return this.totp.setup(userId, email);
  }
  async confirmTOTP(userId, secret, code, backupCodes) {
    return this.totp.confirmSetup(userId, secret, code, backupCodes);
  }
  async verifyTOTP(userId, code) {
    return this.totp.verify(userId, code);
  }
  async disableTOTP(userId) {
    return this.totp.disable(userId);
  }
  // ─── OAuth Convenience Methods ─────────────────────────────────────────
  registerOAuthProvider(name, config) {
    this.oauth.registerProvider(name, config);
  }
  registerOAuthPreset(preset, config) {
    this.oauth.registerPreset(preset, config);
  }
  async getOAuthAuthorizationUrl(provider, metadata) {
    return this.oauth.getAuthorizationUrl(provider, { metadata });
  }
  async handleOAuthCallback(provider, code, state) {
    return this.oauth.handleCallback(provider, code, state);
  }
  // ─── Key Rotation ──────────────────────────────────────────────────────
  rotateJWTKeys(newSecret) {
    this.jwt.rotateKeys(newSecret);
  }
  // ─── Shutdown ──────────────────────────────────────────────────────────
  async close() {
    this.stopCleanup();
    this.oauth.destroy();
    if (this.adapter.close) {
      await this.adapter.close();
    }
  }
  // ─── Internals ─────────────────────────────────────────────────────────
  static ASYMMETRIC_ALGS = /* @__PURE__ */ new Set(["RS256", "ES256", "ES384", "ES512", "EdDSA"]);
  validateAndNormalize(config) {
    if (!config.adapter) {
      throw new ConfigurationError("A database adapter is required");
    }
    const alg = config.jwt?.algorithm ?? "HS256";
    if (!config.jwt?.accessTokenSecret && !_LockVault.ASYMMETRIC_ALGS.has(alg)) {
      throw new ConfigurationError("jwt.accessTokenSecret is required");
    }
    return {
      ...config,
      jwt: {
        algorithm: "HS256",
        accessTokenTTL: 900,
        refreshTokenTTL: 604800,
        ...config.jwt
      },
      session: {
        enabled: true,
        maxPerUser: 10,
        ...config.session
      },
      refreshToken: {
        rotation: true,
        reuseDetection: true,
        familyRevocationOnReuse: true,
        ...config.refreshToken
      }
    };
  }
  mergePluginHooks(plugins) {
    const hooks = {};
    for (const plugin of plugins) {
      if (plugin.hooks) {
        for (const [key, fn] of Object.entries(plugin.hooks)) {
          const hookKey = key;
          const existing = hooks[hookKey];
          if (existing) {
            hooks[hookKey] = (async (...args) => {
              await existing(...args);
              return fn(...args);
            });
          } else {
            hooks[hookKey] = fn;
          }
        }
      }
    }
    return hooks;
  }
};

// src/adapters/memory/index.ts
var MemoryAdapter = class {
  sessions = /* @__PURE__ */ new Map();
  refreshFamilies = /* @__PURE__ */ new Map();
  revocationList = /* @__PURE__ */ new Map();
  totpSecrets = /* @__PURE__ */ new Map();
  backupCodes = /* @__PURE__ */ new Map();
  oauthLinks = /* @__PURE__ */ new Map();
  // userId -> links
  // ─── Sessions ───────────────────────────────────────────────────────────
  async createSession(session) {
    this.sessions.set(session.id, { ...session });
    return { ...session };
  }
  async getSession(sessionId) {
    const s = this.sessions.get(sessionId);
    return s ? { ...s } : null;
  }
  async getSessionsByUser(userId) {
    return [...this.sessions.values()].filter((s) => s.userId === userId).map((s) => ({ ...s }));
  }
  async updateSession(sessionId, updates) {
    const s = this.sessions.get(sessionId);
    if (!s) return null;
    const updated = { ...s, ...updates };
    this.sessions.set(sessionId, updated);
    return { ...updated };
  }
  async deleteSession(sessionId) {
    return this.sessions.delete(sessionId);
  }
  async deleteSessionsByUser(userId) {
    let count = 0;
    for (const [id, s] of this.sessions) {
      if (s.userId === userId) {
        this.sessions.delete(id);
        count++;
      }
    }
    return count;
  }
  async deleteExpiredSessions() {
    const now = /* @__PURE__ */ new Date();
    let count = 0;
    for (const [id, s] of this.sessions) {
      if (s.expiresAt < now || s.isRevoked) {
        this.sessions.delete(id);
        count++;
      }
    }
    return count;
  }
  // ─── Refresh Token Families ─────────────────────────────────────────────
  async storeRefreshTokenFamily(family, userId, generation) {
    this.refreshFamilies.set(family, { userId, generation, revoked: false });
  }
  async getRefreshTokenFamily(family) {
    return this.refreshFamilies.get(family) ?? null;
  }
  async revokeRefreshTokenFamily(family) {
    const record = this.refreshFamilies.get(family);
    if (record) {
      record.revoked = true;
    }
  }
  async incrementRefreshTokenGeneration(family) {
    const record = this.refreshFamilies.get(family);
    if (!record) throw new Error(`Family ${family} not found`);
    record.generation++;
    return record.generation;
  }
  // ─── Revocation List ────────────────────────────────────────────────────
  async addToRevocationList(jti, expiresAt) {
    this.revocationList.set(jti, expiresAt);
  }
  async isRevoked(jti) {
    return this.revocationList.has(jti);
  }
  async cleanupRevocationList() {
    const now = /* @__PURE__ */ new Date();
    let count = 0;
    for (const [jti, exp] of this.revocationList) {
      if (exp < now) {
        this.revocationList.delete(jti);
        count++;
      }
    }
    return count;
  }
  // ─── TOTP ──────────────────────────────────────────────────────────────
  async storeTOTPSecret(userId, secret) {
    this.totpSecrets.set(userId, secret);
  }
  async getTOTPSecret(userId) {
    return this.totpSecrets.get(userId) ?? null;
  }
  async removeTOTPSecret(userId) {
    this.totpSecrets.delete(userId);
    this.backupCodes.delete(userId);
  }
  async storeBackupCodes(userId, codes) {
    this.backupCodes.set(userId, [...codes]);
  }
  async getBackupCodes(userId) {
    return this.backupCodes.get(userId) ?? [];
  }
  async consumeBackupCode(userId, code) {
    const codes = this.backupCodes.get(userId);
    if (!codes) return false;
    const normalized = code.toUpperCase();
    const idx = codes.findIndex((c) => c === normalized);
    if (idx === -1) return false;
    codes.splice(idx, 1);
    return true;
  }
  // ─── OAuth ─────────────────────────────────────────────────────────────
  async linkOAuthAccount(userId, link) {
    const links = this.oauthLinks.get(userId) ?? [];
    const existing = links.findIndex((l) => l.provider === link.provider);
    if (existing >= 0) {
      links[existing] = link;
    } else {
      links.push(link);
    }
    this.oauthLinks.set(userId, links);
  }
  async getOAuthLinks(userId) {
    return this.oauthLinks.get(userId) ?? [];
  }
  async findUserByOAuth(provider, providerUserId) {
    for (const [userId, links] of this.oauthLinks) {
      if (links.some((l) => l.provider === provider && l.providerUserId === providerUserId)) {
        return userId;
      }
    }
    return null;
  }
  async unlinkOAuthAccount(userId, provider) {
    const links = this.oauthLinks.get(userId);
    if (!links) return false;
    const filtered = links.filter((l) => l.provider !== provider);
    if (filtered.length === links.length) return false;
    this.oauthLinks.set(userId, filtered);
    return true;
  }
  // ─── Lifecycle ─────────────────────────────────────────────────────────
  async initialize() {
  }
  async close() {
    this.sessions.clear();
    this.refreshFamilies.clear();
    this.revocationList.clear();
    this.totpSecrets.clear();
    this.backupCodes.clear();
    this.oauthLinks.clear();
  }
};

exports.AuthErrorCode = AuthErrorCode;
exports.ConfigurationError = ConfigurationError;
exports.JWTManager = JWTManager;
exports.LockVault = LockVault;
exports.LockVaultError = LockVaultError;
exports.MemoryAdapter = MemoryAdapter;
exports.MemoryKeyValueStore = MemoryKeyValueStore;
exports.OAuthError = OAuthError;
exports.OAuthManager = OAuthManager;
exports.RateLimitError = RateLimitError;
exports.RateLimiter = RateLimiter;
exports.RefreshTokenReuseError = RefreshTokenReuseError;
exports.SessionError = SessionError;
exports.SessionManager = SessionManager;
exports.TOTPError = TOTPError;
exports.TOTPManager = TOTPManager;
exports.TokenExpiredError = TokenExpiredError;
exports.TokenInvalidError = TokenInvalidError;
exports.TokenRevokedError = TokenRevokedError;
exports.generateBackupCodes = generateBackupCodes;
exports.generateId = generateId;
exports.generateUUID = generateUUID;
exports.hashPassword = hashPassword;
exports.verifyPassword = verifyPassword;
//# sourceMappingURL=index.js.map
//# sourceMappingURL=index.js.map
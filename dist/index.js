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
  AuthErrorCode2["EMAIL_ERROR"] = "EMAIL_ERROR";
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
var EmailError = class extends LockVaultError {
  constructor(message, details) {
    super(message, "EMAIL_ERROR" /* EMAIL_ERROR */, 500, details);
    this.name = "EmailError";
  }
};

// src/utils/crypto.ts
var PROCESS_COMPARE_KEY = crypto.randomBytes(32).toString("hex");
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
  const hmacA = crypto.createHmac("sha256", PROCESS_COMPARE_KEY).update(a).digest();
  const hmacB = crypto.createHmac("sha256", PROCESS_COMPARE_KEY).update(b).digest();
  const hmacEqual = crypto.timingSafeEqual(hmacA, hmacB);
  const lengthEqual = a.length === b.length;
  return hmacEqual && lengthEqual;
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
  const version = Buffer.from([1]);
  return Buffer.concat([version, iv, authTag, encrypted]).toString("base64url");
}
function decrypt(ciphertext, keyHex) {
  if (keyHex.length !== 64) {
    throw new ConfigurationError("Encryption key must be 32 bytes (64 hex characters)");
  }
  try {
    const key = Buffer.from(keyHex, "hex");
    const data = Buffer.from(ciphertext, "base64url");
    let iv, authTag, encrypted;
    if (data[0] === 1 && data.length > 29) {
      iv = data.subarray(1, 13);
      authTag = data.subarray(13, 29);
      encrypted = data.subarray(29);
    } else {
      iv = data.subarray(0, 12);
      authTag = data.subarray(12, 28);
      encrypted = data.subarray(28);
    }
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(authTag);
    return decipher.update(encrypted) + decipher.final("utf8");
  } catch {
    throw new LockVaultError("Failed to decrypt token", "ENCRYPTION_ERROR" /* ENCRYPTION_ERROR */, 401);
  }
}
async function hashPassword(password, options) {
  const N = options?.N ?? 32768;
  const r = options?.r ?? 8;
  const p = options?.p ?? 2;
  const salt = crypto.randomBytes(32).toString("hex");
  const derived = await new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, { N, r, p, maxmem: N * r * 256 }, (err, key) => {
      if (err) reject(err);
      else resolve(key);
    });
  });
  return `scrypt:${N}:${r}:${p}:${salt}:${derived.toString("hex")}`;
}
async function verifyPassword(password, hash) {
  let salt, key, N, r, p;
  if (hash.startsWith("scrypt:")) {
    const parts = hash.split(":");
    if (parts.length !== 6) return false;
    N = parseInt(parts[1], 10);
    r = parseInt(parts[2], 10);
    p = parseInt(parts[3], 10);
    salt = parts[4];
    key = parts[5];
    if (isNaN(N) || isNaN(r) || isNaN(p)) return false;
  } else {
    const parts = hash.split(":");
    if (parts.length !== 2) return false;
    salt = parts[0];
    key = parts[1];
    N = 16384;
    r = 8;
    p = 1;
  }
  if (!salt || !key) return false;
  const derived = await new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, { N, r, p, maxmem: N * r * 256 }, (err, derivedKey) => {
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
function generateTokenFingerprint(ipAddress, userAgent) {
  const data = `${ipAddress ?? "unknown"}|${userAgent ?? "unknown"}`;
  return crypto.createHash("sha256").update(data).digest("base64url").slice(0, 16);
}
function sanitizeIpAddress(ip) {
  if (!ip || typeof ip !== "string") return void 0;
  const cleaned = ip.trim().split(",")[0]?.trim();
  if (!cleaned || cleaned.length > 45) return void 0;
  const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const v4Match = cleaned.match(ipv4Regex);
  if (v4Match) {
    const valid = [v4Match[1], v4Match[2], v4Match[3], v4Match[4]].every((o) => parseInt(o, 10) <= 255);
    return valid ? cleaned : void 0;
  }
  const ipv6Regex = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
  if (ipv6Regex.test(cleaned)) return cleaned;
  const mappedRegex = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i;
  const mappedMatch = cleaned.match(mappedRegex);
  if (mappedMatch) return mappedMatch[1];
  return void 0;
}
function generatePKCE() {
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
  return { codeVerifier, codeChallenge, codeChallengeMethod: "S256" };
}
function generateCSRFToken() {
  return crypto.randomBytes(32).toString("base64url");
}

// src/jwt/index.ts
function base64UrlEncode(data) {
  const buf = typeof data === "string" ? Buffer.from(data) : data;
  return buf.toString("base64url");
}
function base64UrlDecode(str) {
  return Buffer.from(str, "base64url").toString("utf8");
}
var ASYMMETRIC_ALGS = /* @__PURE__ */ new Set(["RS256", "ES256", "ES384", "ES512", "EdDSA"]);
function deriveKid(secret) {
  return crypto.createHash("sha256").update(secret).digest("base64url").slice(0, 8);
}
function createJWTManager(config, hooks = {}) {
  const adapter = config.adapter;
  let previousSecrets = [];
  const alg = config.jwt.algorithm ?? "HS256";
  if (ASYMMETRIC_ALGS.has(alg)) {
    if (!config.jwt.privateKey || !config.jwt.publicKey) throw new ConfigurationError(`privateKey and publicKey are required for ${alg}`);
  } else {
    if (!config.jwt.accessTokenSecret) throw new ConfigurationError(`accessTokenSecret is required for ${alg}`);
    if (config.jwt.accessTokenSecret.length < 32) throw new ConfigurationError(`accessTokenSecret must be at least 32 characters for ${alg}`);
    if (config.jwt.refreshTokenSecret && config.jwt.refreshTokenSecret.length < 32) throw new ConfigurationError(`refreshTokenSecret must be at least 32 characters for ${alg}`);
  }
  function signToken(payload, secret) {
    const algorithm = config.jwt.algorithm ?? "HS256";
    const kid = ASYMMETRIC_ALGS.has(algorithm) ? void 0 : deriveKid(secret);
    const header = { alg: algorithm, typ: "JWT" };
    if (kid) header.kid = kid;
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
        const s = crypto.createSign("RSA-SHA256");
        s.update(signingInput);
        signature = s.sign(config.jwt.privateKey, "base64url");
        break;
      }
      case "ES256": {
        const s = crypto.createSign("SHA256");
        s.update(signingInput);
        signature = s.sign({ key: config.jwt.privateKey, dsaEncoding: "ieee-p1363" }, "base64url");
        break;
      }
      case "ES384": {
        const s = crypto.createSign("SHA384");
        s.update(signingInput);
        signature = s.sign({ key: config.jwt.privateKey, dsaEncoding: "ieee-p1363" }, "base64url");
        break;
      }
      case "ES512": {
        const s = crypto.createSign("SHA512");
        s.update(signingInput);
        signature = s.sign({ key: config.jwt.privateKey, dsaEncoding: "ieee-p1363" }, "base64url");
        break;
      }
      case "EdDSA": {
        const edSig = crypto.sign(null, inputBuf, config.jwt.privateKey);
        signature = edSig.toString("base64url");
        break;
      }
      default:
        throw new ConfigurationError(`Unsupported algorithm: ${algorithm}`);
    }
    return `${signingInput}.${signature}`;
  }
  function verifySignature(algorithm, signingInput, signature, secret, kid) {
    const sigBuf = Buffer.from(signature, "base64url");
    const inputBuf = Buffer.from(signingInput);
    switch (algorithm) {
      case "HS256": {
        const allSecrets = kid ? [
          ...deriveKid(secret) === kid ? [secret] : [],
          ...previousSecrets.filter((s) => s.kid === kid).map((s) => s.secret),
          // Fallback: try all if kid didn't match (handles legacy tokens)
          ...deriveKid(secret) !== kid ? [secret] : [],
          ...previousSecrets.filter((s) => s.kid !== kid).map((s) => s.secret)
        ] : [secret, ...previousSecrets.map((s) => s.secret)];
        for (const s of allSecrets) {
          const expected = crypto.createHmac("sha256", s).update(signingInput).digest("base64url");
          if (safeCompare(expected, signature)) return true;
        }
        return false;
      }
      case "RS256": {
        const v = crypto.createVerify("RSA-SHA256");
        v.update(signingInput);
        return v.verify(config.jwt.publicKey, sigBuf);
      }
      case "ES256": {
        const v = crypto.createVerify("SHA256");
        v.update(signingInput);
        return v.verify({ key: config.jwt.publicKey, dsaEncoding: "ieee-p1363" }, sigBuf);
      }
      case "ES384": {
        const v = crypto.createVerify("SHA384");
        v.update(signingInput);
        return v.verify({ key: config.jwt.publicKey, dsaEncoding: "ieee-p1363" }, sigBuf);
      }
      case "ES512": {
        const v = crypto.createVerify("SHA512");
        v.update(signingInput);
        return v.verify({ key: config.jwt.publicKey, dsaEncoding: "ieee-p1363" }, sigBuf);
      }
      case "EdDSA":
        return crypto.verify(null, inputBuf, config.jwt.publicKey, sigBuf);
      default:
        return false;
    }
  }
  function verifyToken(token, secret) {
    const parts = token.split(".");
    if (parts.length !== 3) throw new TokenInvalidError("Token must have 3 parts");
    const [headerB64, payloadB64, signature] = parts;
    const signingInput = `${headerB64}.${payloadB64}`;
    const algorithm = config.jwt.algorithm ?? "HS256";
    let header;
    try {
      header = JSON.parse(base64UrlDecode(headerB64));
    } catch {
      throw new TokenInvalidError("Malformed token header");
    }
    if (header.alg !== algorithm) throw new TokenInvalidError(`Algorithm mismatch: expected "${algorithm}"`);
    if (!verifySignature(algorithm, signingInput, signature, secret, header.kid)) {
      throw new TokenInvalidError("Invalid signature");
    }
    const payload = JSON.parse(base64UrlDecode(payloadB64));
    const now = Math.floor(Date.now() / 1e3);
    if (payload.exp && payload.exp < now) throw new TokenExpiredError();
    if (payload.nbf && payload.nbf > now) throw new TokenInvalidError("Token is not yet valid");
    const expectedIssuer = config.jwt.issuer;
    if (expectedIssuer && payload.iss !== expectedIssuer) throw new TokenInvalidError("Issuer mismatch");
    const expectedAudience = config.jwt.audience;
    if (expectedAudience) {
      const tokenAud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
      if (!tokenAud.includes(expectedAudience)) throw new TokenInvalidError("Audience mismatch");
    }
    return payload;
  }
  return {
    async createTokenPair(userId, customClaims = {}, sessionId) {
      const now = Math.floor(Date.now() / 1e3);
      const jwtConfig = config.jwt;
      const accessTTL = jwtConfig.accessTokenTTL ?? 900;
      const refreshTTL = jwtConfig.refreshTokenTTL ?? 604800;
      let claims = { ...customClaims };
      if (hooks.beforeTokenCreate) claims = await hooks.beforeTokenCreate(claims);
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
      const accessToken = signToken(accessPayload, jwtConfig.accessTokenSecret);
      let refreshToken = signToken(refreshPayload, jwtConfig.refreshTokenSecret ?? jwtConfig.accessTokenSecret);
      const encConfig = config.refreshToken?.encryption;
      if (encConfig?.enabled) refreshToken = encrypt(refreshToken, encConfig.key);
      await adapter.storeRefreshTokenFamily(family, userId, 0);
      const tokenPair = {
        accessToken,
        refreshToken,
        accessTokenExpiresAt: new Date((now + accessTTL) * 1e3),
        refreshTokenExpiresAt: new Date((now + refreshTTL) * 1e3)
      };
      if (hooks.afterTokenCreate) await hooks.afterTokenCreate(tokenPair);
      return tokenPair;
    },
    async verifyAccessToken(token) {
      let processedToken = token;
      if (hooks.beforeTokenVerify) processedToken = await hooks.beforeTokenVerify(processedToken);
      const payload = verifyToken(processedToken, config.jwt.accessTokenSecret);
      if (payload.type !== "access") throw new TokenInvalidError("Expected access token");
      if (await adapter.isRevoked(payload.jti)) throw new TokenRevokedError();
      if (hooks.afterTokenVerify) await hooks.afterTokenVerify(payload);
      return payload;
    },
    async verifyRefreshToken(token) {
      let processedToken = token;
      const encConfig = config.refreshToken?.encryption;
      if (encConfig?.enabled) processedToken = decrypt(processedToken, encConfig.key);
      const secret = config.jwt.refreshTokenSecret ?? config.jwt.accessTokenSecret;
      const payload = verifyToken(processedToken, secret);
      if (payload.type !== "refresh") throw new TokenInvalidError("Expected refresh token");
      return payload;
    },
    async refreshTokens(refreshToken, customClaims = {}) {
      const payload = await this.verifyRefreshToken(refreshToken);
      const { family, generation, sub: userId } = payload;
      const familyRecord = await adapter.getRefreshTokenFamily(family);
      if (!familyRecord) throw new TokenInvalidError("Unknown refresh token family");
      if (familyRecord.revoked) throw new TokenRevokedError("Refresh token family has been revoked");
      const reuseConfig = config.refreshToken;
      if (reuseConfig?.reuseDetection !== false && generation < familyRecord.generation) {
        if (reuseConfig?.familyRevocationOnReuse !== false) {
          await adapter.revokeRefreshTokenFamily(family);
          await adapter.deleteSessionsByUser(userId);
        }
        if (hooks.onReuseDetected) await hooks.onReuseDetected(family, userId);
        throw new RefreshTokenReuseError(family);
      }
      const now = Math.floor(Date.now() / 1e3);
      const jwtConfig = config.jwt;
      const accessTTL = jwtConfig.accessTokenTTL ?? 900;
      const refreshTTL = jwtConfig.refreshTokenTTL ?? 604800;
      let claims = { ...customClaims };
      if (hooks.beforeTokenCreate) claims = await hooks.beforeTokenCreate(claims);
      const newGeneration = await adapter.incrementRefreshTokenGeneration(family);
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
      const newAccessToken = signToken(accessPayload, jwtConfig.accessTokenSecret);
      let newRefreshToken = signToken(refreshPayload, jwtConfig.refreshTokenSecret ?? jwtConfig.accessTokenSecret);
      const encConfig = config.refreshToken?.encryption;
      if (encConfig?.enabled) newRefreshToken = encrypt(newRefreshToken, encConfig.key);
      const tokenPair = {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
        accessTokenExpiresAt: new Date((now + accessTTL) * 1e3),
        refreshTokenExpiresAt: new Date((now + refreshTTL) * 1e3)
      };
      if (hooks.afterTokenCreate) await hooks.afterTokenCreate(tokenPair);
      return tokenPair;
    },
    async revokeToken(token) {
      const parts = token.split(".");
      if (parts.length !== 3) throw new TokenInvalidError("Cannot revoke: token is malformed");
      const [headerB64, payloadB64, signature] = parts;
      const signingInput = `${headerB64}.${payloadB64}`;
      const algorithm = config.jwt.algorithm ?? "HS256";
      let header;
      try {
        header = JSON.parse(base64UrlDecode(headerB64));
      } catch {
        throw new TokenInvalidError("Cannot revoke: token is malformed");
      }
      if (header.alg !== algorithm) throw new TokenInvalidError("Cannot revoke: algorithm mismatch");
      let payload;
      try {
        payload = JSON.parse(base64UrlDecode(payloadB64));
      } catch {
        throw new TokenInvalidError("Cannot revoke: token is malformed");
      }
      const secret = payload.type === "refresh" ? config.jwt.refreshTokenSecret ?? config.jwt.accessTokenSecret : config.jwt.accessTokenSecret;
      if (!verifySignature(algorithm, signingInput, signature, secret, header.kid)) {
        throw new TokenInvalidError("Cannot revoke: invalid signature");
      }
      await adapter.addToRevocationList(payload.jti, new Date(payload.exp * 1e3));
      if (payload.type === "refresh") {
        const rp = payload;
        await adapter.revokeRefreshTokenFamily(rp.family);
      }
      if (hooks.onTokenRevoked) await hooks.onTokenRevoked(payload.jti);
    },
    rotateKeys(newSecret) {
      if (newSecret.length < 32) throw new ConfigurationError("New secret must be at least 32 characters");
      previousSecrets.push({ secret: config.jwt.accessTokenSecret, kid: deriveKid(config.jwt.accessTokenSecret) });
      config.jwt.accessTokenSecret = newSecret;
      if (previousSecrets.length > 3) previousSecrets.shift();
    },
    decode(token) {
      const parts = token.split(".");
      if (parts.length !== 3) throw new TokenInvalidError("Token must have 3 parts");
      try {
        const header = JSON.parse(base64UrlDecode(parts[0]));
        const payload = JSON.parse(base64UrlDecode(parts[1]));
        return { header, payload, signature: parts[2] };
      } catch {
        throw new TokenInvalidError("Failed to decode token");
      }
    }
  };
}

// src/session/index.ts
function createSessionManager(config, hooks = {}) {
  const adapter = config.adapter;
  return {
    async createSession(userId, refreshTokenFamily, options = {}) {
      const sessionConfig = config.session;
      if (sessionConfig?.maxPerUser) {
        const existing = await adapter.getSessionsByUser(userId);
        const active = existing.filter((s) => !s.isRevoked && s.expiresAt > /* @__PURE__ */ new Date());
        if (active.length >= sessionConfig.maxPerUser) {
          const oldest = active.sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime())[0];
          if (oldest) await adapter.deleteSession(oldest.id);
        }
      }
      const ttl = options.expiresInSeconds ?? config.jwt.refreshTokenTTL ?? 604800;
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
      if (hooks.beforeSessionCreate) sessionData = await hooks.beforeSessionCreate(sessionData);
      const session = await adapter.createSession(sessionData);
      if (hooks.afterSessionCreate) await hooks.afterSessionCreate(session);
      return session;
    },
    async getSession(sessionId) {
      const session = await adapter.getSession(sessionId);
      if (!session) throw new SessionError("Session not found", "SESSION_NOT_FOUND" /* SESSION_NOT_FOUND */);
      if (session.isRevoked) throw new SessionError("Session has been revoked", "SESSION_REVOKED" /* SESSION_REVOKED */);
      if (session.expiresAt < /* @__PURE__ */ new Date()) throw new SessionError("Session has expired", "SESSION_EXPIRED" /* SESSION_EXPIRED */);
      const absoluteTimeout = config.session?.absoluteTimeout;
      if (absoluteTimeout) {
        const ageMs = Date.now() - session.createdAt.getTime();
        if (ageMs > absoluteTimeout * 1e3) {
          await adapter.updateSession(sessionId, { isRevoked: true });
          throw new SessionError("Session exceeded maximum lifetime", "SESSION_EXPIRED" /* SESSION_EXPIRED */);
        }
      }
      const inactivityTimeout = config.session?.inactivityTimeout;
      if (inactivityTimeout) {
        const inactiveMs = Date.now() - session.lastActiveAt.getTime();
        if (inactiveMs > inactivityTimeout * 1e3) {
          await adapter.updateSession(sessionId, { isRevoked: true });
          throw new SessionError("Session expired due to inactivity", "SESSION_EXPIRED" /* SESSION_EXPIRED */);
        }
      }
      return session;
    },
    async touchSession(sessionId) {
      const session = await adapter.getSession(sessionId);
      if (!session || session.isRevoked || session.expiresAt < /* @__PURE__ */ new Date()) return null;
      return adapter.updateSession(sessionId, { lastActiveAt: /* @__PURE__ */ new Date() });
    },
    async getUserSessions(userId) {
      const sessions = await adapter.getSessionsByUser(userId);
      return sessions.filter((s) => !s.isRevoked && s.expiresAt > /* @__PURE__ */ new Date());
    },
    async revokeSession(sessionId) {
      const u = await adapter.updateSession(sessionId, { isRevoked: true });
      return u !== null;
    },
    async revokeAllSessions(userId) {
      return adapter.deleteSessionsByUser(userId);
    },
    async cleanup() {
      return adapter.deleteExpiredSessions();
    }
  };
}

// src/ratelimit/index.ts
var RateLimitError = class _RateLimitError extends LockVaultError {
  retryAfterMs;
  constructor(identifier, retryAfterMs) {
    super(`Rate limit exceeded for "${identifier}". Retry after ${Math.ceil(retryAfterMs / 1e3)}s.`, "RATE_LIMITED" /* RATE_LIMITED */, 429, { identifier, retryAfterMs });
    this.name = "RateLimitError";
    this.retryAfterMs = retryAfterMs;
    Object.setPrototypeOf(this, _RateLimitError.prototype);
  }
};
function createRateLimiter(config = {}) {
  const windowMs = config.windowMs ?? 6e4;
  const maxAttempts = config.maxAttempts ?? 5;
  const onRateLimit = config.onRateLimit;
  const store = /* @__PURE__ */ new Map();
  let cleanupTimer = setInterval(() => cleanup(), 3e5);
  if (cleanupTimer?.unref) cleanupTimer.unref();
  function cleanup() {
    const now = Date.now();
    const windowStart = now - windowMs;
    for (const [key, entry] of store) {
      entry.timestamps = entry.timestamps.filter((t) => t > windowStart);
      if (entry.timestamps.length === 0) store.delete(key);
    }
  }
  return {
    async consume(identifier) {
      const now = Date.now();
      const windowStart = now - windowMs;
      let entry = store.get(identifier);
      if (!entry) {
        entry = { timestamps: [] };
        store.set(identifier, entry);
      }
      entry.timestamps = entry.timestamps.filter((t) => t > windowStart);
      if (entry.timestamps.length >= maxAttempts) {
        const oldestInWindow = entry.timestamps[0];
        const retryAfterMs = oldestInWindow + windowMs - now;
        if (onRateLimit) await onRateLimit(identifier);
        throw new RateLimitError(identifier, retryAfterMs);
      }
      entry.timestamps.push(now);
    },
    reset(identifier) {
      store.delete(identifier);
    },
    remaining(identifier) {
      const now = Date.now();
      const windowStart = now - windowMs;
      const entry = store.get(identifier);
      if (!entry) return maxAttempts;
      const recent = entry.timestamps.filter((t) => t > windowStart).length;
      return Math.max(0, maxAttempts - recent);
    },
    cleanup,
    destroy() {
      if (cleanupTimer) {
        clearInterval(cleanupTimer);
        cleanupTimer = void 0;
      }
      store.clear();
    }
  };
}

// src/store/index.ts
function createMemoryKeyValueStore(options = {}) {
  const maxEntries = options.maxEntries ?? 5e4;
  const store = /* @__PURE__ */ new Map();
  function cleanup() {
    const now = Date.now();
    for (const [key, entry] of store) {
      if (entry.expiresAt && entry.expiresAt < now) store.delete(key);
    }
  }
  let cleanupTimer = setInterval(
    () => cleanup(),
    options.cleanupIntervalMs ?? 6e4
  );
  if (cleanupTimer.unref) cleanupTimer.unref();
  return {
    async get(key) {
      const entry = store.get(key);
      if (!entry) return null;
      if (entry.expiresAt && entry.expiresAt < Date.now()) {
        store.delete(key);
        return null;
      }
      return entry.value;
    },
    async set(key, value, ttlMs) {
      if (store.size >= maxEntries) {
        cleanup();
        if (store.size >= maxEntries) {
          const toRemove = store.size - maxEntries + 1;
          const keys = store.keys();
          for (let i = 0; i < toRemove; i++) {
            const k = keys.next().value;
            if (k) store.delete(k);
          }
        }
      }
      store.set(key, { value, expiresAt: ttlMs ? Date.now() + ttlMs : void 0 });
    },
    async delete(key) {
      return store.delete(key);
    },
    destroy() {
      if (cleanupTimer) {
        clearInterval(cleanupTimer);
        cleanupTimer = void 0;
      }
      store.clear();
    }
  };
}

// src/totp/index.ts
var DEFAULT_TOTP_CONFIG = { issuer: "LockVault", algorithm: "SHA1", digits: 6, period: 30, window: 1 };
function createTOTPManager(cfg = {}, adapter, kvStore) {
  const c = { ...DEFAULT_TOTP_CONFIG, ...cfg };
  const rateLimiter = createRateLimiter({ windowMs: 6e4, maxAttempts: 5 });
  const replayStore = kvStore ?? createMemoryKeyValueStore({ maxEntries: 5e4 });
  function generateSecret(bytes = 20) {
    return base32Encode(crypto.randomBytes(bytes));
  }
  function buildURI(secret, accountName) {
    const params = new URLSearchParams({ secret, issuer: c.issuer, algorithm: c.algorithm, digits: String(c.digits), period: String(c.period) });
    const label = `${encodeURIComponent(c.issuer)}:${encodeURIComponent(accountName)}`;
    return `otpauth://totp/${label}?${params.toString()}`;
  }
  function hotpGenerate(secret, counter) {
    const key = base32Decode(secret);
    const counterBuffer = Buffer.alloc(8);
    counterBuffer.writeBigUInt64BE(BigInt(counter));
    const algMap = { SHA1: "sha1", SHA256: "sha256", SHA512: "sha512" };
    const hmac = crypto.createHmac(algMap[c.algorithm], key);
    hmac.update(counterBuffer);
    const hash = hmac.digest();
    const offset = hash[hash.length - 1] & 15;
    const binary = (hash[offset] & 127) << 24 | (hash[offset + 1] & 255) << 16 | (hash[offset + 2] & 255) << 8 | hash[offset + 3] & 255;
    const otp = binary % Math.pow(10, c.digits);
    return otp.toString().padStart(c.digits, "0");
  }
  function verifyCode(secret, code) {
    const now = Math.floor(Date.now() / 1e3);
    const counter = Math.floor(now / c.period);
    let valid = false;
    for (let i = -c.window; i <= c.window; i++) {
      const expected = hotpGenerate(secret, counter + i);
      if (expected.length === code.length && safeCompare(expected, code)) valid = true;
    }
    return valid;
  }
  return {
    async setup(userId, userEmail) {
      const existing = await adapter.getTOTPSecret(userId);
      if (existing) throw new TOTPError("TOTP is already enabled for this user", "TOTP_ALREADY_ENABLED" /* TOTP_ALREADY_ENABLED */);
      const secret = generateSecret();
      const uri = buildURI(secret, userEmail ?? userId);
      const backupCodes = generateBackupCodes(10);
      return { secret, uri, backupCodes };
    },
    async confirmSetup(userId, secret, code, backupCodes) {
      if (!verifyCode(secret, code)) throw new TOTPError("Invalid TOTP code", "TOTP_INVALID" /* TOTP_INVALID */);
      await adapter.storeTOTPSecret(userId, secret);
      await adapter.storeBackupCodes(userId, backupCodes);
      return true;
    },
    async verify(userId, code) {
      await rateLimiter.consume(`totp:${userId}`);
      const secret = await adapter.getTOTPSecret(userId);
      if (!secret) throw new TOTPError("TOTP is not enabled for this user", "TOTP_NOT_ENABLED" /* TOTP_NOT_ENABLED */);
      if (verifyCode(secret, code)) {
        const codeKey = `totp_used:${userId}:${code}`;
        const alreadyUsed = await replayStore.get(codeKey);
        if (alreadyUsed) throw new TOTPError("TOTP code already used", "TOTP_INVALID" /* TOTP_INVALID */);
        await replayStore.set(codeKey, "1", c.period * 2 * 1e3);
        rateLimiter.reset(`totp:${userId}`);
        return true;
      }
      const consumed = await adapter.consumeBackupCode(userId, code);
      if (consumed) {
        rateLimiter.reset(`totp:${userId}`);
        return true;
      }
      throw new TOTPError("Invalid TOTP or backup code", "TOTP_INVALID" /* TOTP_INVALID */);
    },
    async disable(userId) {
      const secret = await adapter.getTOTPSecret(userId);
      if (!secret) throw new TOTPError("TOTP is not enabled for this user", "TOTP_NOT_ENABLED" /* TOTP_NOT_ENABLED */);
      await adapter.removeTOTPSecret(userId);
    },
    async getBackupCodesCount(userId) {
      return (await adapter.getBackupCodes(userId)).length;
    },
    async regenerateBackupCodes(userId) {
      const secret = await adapter.getTOTPSecret(userId);
      if (!secret) throw new TOTPError("TOTP is not enabled for this user", "TOTP_NOT_ENABLED" /* TOTP_NOT_ENABLED */);
      const codes = generateBackupCodes(10);
      await adapter.storeBackupCodes(userId, codes);
      return codes;
    },
    generateCode(secret, time) {
      const now = time ?? Math.floor(Date.now() / 1e3);
      const counter = Math.floor(now / c.period);
      return hotpGenerate(secret, counter);
    }
  };
}

// src/oauth/index.ts
var PROVIDER_PRESETS = {
  google: { authorizationUrl: "https://accounts.google.com/o/oauth2/v2/auth", tokenUrl: "https://oauth2.googleapis.com/token", userInfoUrl: "https://www.googleapis.com/oauth2/v2/userinfo", scopes: ["openid", "email", "profile"], pkce: true, mapProfile: (p) => ({ id: String(p.id), email: String(p.email ?? ""), name: String(p.name ?? ""), avatar: String(p.picture ?? ""), raw: p }) },
  github: { authorizationUrl: "https://github.com/login/oauth/authorize", tokenUrl: "https://github.com/login/oauth/access_token", userInfoUrl: "https://api.github.com/user", scopes: ["read:user", "user:email"], pkce: false, mapProfile: (p) => ({ id: String(p.id), email: String(p.email ?? ""), name: String(p.name ?? p.login ?? ""), avatar: String(p.avatar_url ?? ""), raw: p }) },
  facebook: { authorizationUrl: "https://www.facebook.com/v18.0/dialog/oauth", tokenUrl: "https://graph.facebook.com/v18.0/oauth/access_token", userInfoUrl: "https://graph.facebook.com/me?fields=id,name,email,picture", scopes: ["email", "public_profile"], pkce: false, mapProfile: (p) => ({ id: String(p.id), email: String(p.email ?? ""), name: String(p.name ?? ""), avatar: p.picture?.data?.url ?? "", raw: p }) },
  apple: { authorizationUrl: "https://appleid.apple.com/auth/authorize", tokenUrl: "https://appleid.apple.com/auth/token", userInfoUrl: "", scopes: ["name", "email"], pkce: true, mapProfile: (p) => ({ id: String(p.sub), email: String(p.email ?? ""), name: String(p.name ?? ""), raw: p }) },
  microsoft: { authorizationUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize", tokenUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/token", userInfoUrl: "https://graph.microsoft.com/v1.0/me", scopes: ["openid", "email", "profile"], pkce: true, mapProfile: (p) => ({ id: String(p.id), email: String(p.mail ?? p.userPrincipalName ?? ""), name: String(p.displayName ?? ""), raw: p }) }
};
function createOAuthManager(providerConfigs = {}, adapter, externalStateStore) {
  const providers = /* @__PURE__ */ new Map();
  const ownsStateStore = !externalStateStore;
  const stateStore = externalStateStore ?? createMemoryKeyValueStore({ maxEntries: 1e4 });
  for (const [name, cfg] of Object.entries(providerConfigs)) providers.set(name, cfg);
  function getProvider(name) {
    const p = providers.get(name);
    if (!p) throw new OAuthError(`OAuth provider '${name}' is not registered`);
    return p;
  }
  async function exchangeCode(provider, code, codeVerifier) {
    const params = {
      grant_type: "authorization_code",
      code,
      redirect_uri: provider.redirectUri,
      client_id: provider.clientId,
      client_secret: provider.clientSecret
    };
    if (codeVerifier) params.code_verifier = codeVerifier;
    const body = new URLSearchParams(params);
    const response = await fetch(provider.tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body: body.toString()
    });
    if (!response.ok) {
      throw new OAuthError(`Token exchange failed (HTTP ${response.status})`, { provider: provider.clientId });
    }
    return response.json();
  }
  async function fetchProfile(provider, accessToken) {
    if (!provider.userInfoUrl) throw new OAuthError("Provider does not support user info endpoint");
    const response = await fetch(provider.userInfoUrl, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    if (!response.ok) throw new OAuthError(`Failed to fetch user profile (HTTP ${response.status})`);
    const data = await response.json();
    return provider.mapProfile(data);
  }
  return {
    destroy() {
      if (ownsStateStore && stateStore.destroy) stateStore.destroy();
    },
    registerPreset(preset, config) {
      const base = PROVIDER_PRESETS[preset];
      providers.set(preset, { ...base, ...config, scopes: config.scopes ?? base.scopes });
    },
    registerProvider(name, config) {
      providers.set(name, config);
    },
    async getAuthorizationUrl(providerName, options = {}) {
      const provider = getProvider(providerName);
      const state = options.state ?? generateId(32);
      let codeVerifier;
      let codeChallenge;
      let codeChallengeMethod;
      if (provider.pkce !== false) {
        const pkce = generatePKCE();
        codeVerifier = pkce.codeVerifier;
        codeChallenge = pkce.codeChallenge;
        codeChallengeMethod = pkce.codeChallengeMethod;
      }
      const stateData = JSON.stringify({
        provider: providerName,
        metadata: options.metadata,
        codeVerifier,
        createdAt: Date.now()
      });
      await stateStore.set(`oauth_state:${state}`, stateData, 6e5);
      const params = {
        client_id: provider.clientId,
        redirect_uri: provider.redirectUri,
        response_type: "code",
        state
      };
      if (provider.scopes?.length) params.scope = provider.scopes.join(" ");
      if (codeChallenge) {
        params.code_challenge = codeChallenge;
        params.code_challenge_method = codeChallengeMethod;
      }
      return `${provider.authorizationUrl}?${new URLSearchParams(params).toString()}`;
    },
    async handleCallback(providerName, code, state) {
      const raw = await stateStore.get(`oauth_state:${state}`);
      if (!raw) throw new OAuthError("Invalid or expired OAuth state", { provider: providerName });
      const stateData = JSON.parse(raw);
      if (stateData.provider !== providerName) throw new OAuthError("Invalid or expired OAuth state", { provider: providerName });
      if (stateData.createdAt && Date.now() - stateData.createdAt > 6e5) {
        await stateStore.delete(`oauth_state:${state}`);
        throw new OAuthError("OAuth state has expired", { provider: providerName });
      }
      await stateStore.delete(`oauth_state:${state}`);
      const provider = getProvider(providerName);
      const tokens = await exchangeCode(provider, code, stateData.codeVerifier);
      const profile = await fetchProfile(provider, tokens.access_token);
      return { profile, tokens };
    },
    async linkAccount(userId, providerName, profile, tokens) {
      const link = {
        provider: providerName,
        providerUserId: profile.id,
        accessToken: tokens.access_token,
        refreshToken: tokens.refresh_token,
        profile: profile.raw,
        linkedAt: /* @__PURE__ */ new Date()
      };
      await adapter.linkOAuthAccount(userId, link);
    },
    async findUserByOAuth(providerName, providerUserId) {
      return adapter.findUserByOAuth(providerName, providerUserId);
    },
    async unlinkAccount(userId, providerName) {
      return adapter.unlinkOAuthAccount(userId, providerName);
    },
    async getLinkedProviders(userId) {
      return adapter.getOAuthLinks(userId);
    }
  };
}

// src/core/index.ts
function createLockVault(config) {
  const ASYMMETRIC_ALGS2 = /* @__PURE__ */ new Set(["RS256", "ES256", "ES384", "ES512", "EdDSA"]);
  if (!config.adapter) throw new ConfigurationError("A database adapter is required");
  const alg = config.jwt?.algorithm ?? "HS256";
  if (!config.jwt?.accessTokenSecret && !ASYMMETRIC_ALGS2.has(alg)) throw new ConfigurationError("jwt.accessTokenSecret is required");
  const normalizedConfig = {
    ...config,
    jwt: { algorithm: "HS256", accessTokenTTL: 900, refreshTokenTTL: 604800, ...config.jwt },
    session: { enabled: true, maxPerUser: 10, ...config.session },
    refreshToken: { rotation: true, reuseDetection: true, familyRevocationOnReuse: true, ...config.refreshToken }
  };
  const hooks = {};
  for (const plugin of config.plugins ?? []) {
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
  const adapter = config.adapter;
  const jwt = createJWTManager(normalizedConfig, hooks);
  const sessions = createSessionManager(normalizedConfig, hooks);
  const totp = createTOTPManager(normalizedConfig.totp ?? {}, adapter, normalizedConfig.kvStore);
  const oauth = createOAuthManager(normalizedConfig.oauth?.providers ?? {}, adapter, normalizedConfig.oauth?.stateStore);
  let cleanupInterval;
  return {
    jwt,
    sessions,
    totp,
    oauth,
    adapter,
    async initialize() {
      if (adapter.initialize) await adapter.initialize();
    },
    startCleanup(intervalMs = 36e5) {
      this.stopCleanup();
      cleanupInterval = setInterval(async () => {
        try {
          await adapter.deleteExpiredSessions();
          await adapter.cleanupRevocationList();
        } catch (err) {
          if (hooks.onError) await hooks.onError(err, "cleanup");
        }
      }, intervalMs);
      if (cleanupInterval.unref) cleanupInterval.unref();
    },
    stopCleanup() {
      if (cleanupInterval) {
        clearInterval(cleanupInterval);
        cleanupInterval = void 0;
      }
    },
    async login(userId, options = {}) {
      const session = await sessions.createSession(userId, generateId(16), { deviceInfo: options.deviceInfo, ipAddress: options.ipAddress, metadata: options.metadata });
      const tokens = await jwt.createTokenPair(userId, { ...options.customClaims, sid: session.id }, session.id);
      return { tokens, session };
    },
    async refresh(refreshToken, customClaims) {
      return jwt.refreshTokens(refreshToken, customClaims);
    },
    async logout(accessToken) {
      try {
        const payload = await jwt.verifyAccessToken(accessToken);
        await jwt.revokeToken(accessToken);
        if (payload.sid) await sessions.revokeSession(payload.sid);
      } catch {
      }
    },
    async logoutAll(userId) {
      return sessions.revokeAllSessions(userId);
    },
    async setupTOTP(userId, email) {
      return totp.setup(userId, email);
    },
    async confirmTOTP(userId, secret, code, backupCodes) {
      return totp.confirmSetup(userId, secret, code, backupCodes);
    },
    async verifyTOTP(userId, code) {
      return totp.verify(userId, code);
    },
    async disableTOTP(userId) {
      return totp.disable(userId);
    },
    registerOAuthProvider(name, cfg) {
      oauth.registerProvider(name, cfg);
    },
    registerOAuthPreset(preset, cfg) {
      oauth.registerPreset(preset, cfg);
    },
    async getOAuthAuthorizationUrl(provider, metadata) {
      return oauth.getAuthorizationUrl(provider, { metadata });
    },
    async handleOAuthCallback(provider, code, state) {
      return oauth.handleCallback(provider, code, state);
    },
    rotateJWTKeys(newSecret) {
      jwt.rotateKeys(newSecret);
    },
    async close() {
      this.stopCleanup();
      oauth.destroy();
      if (adapter.close) await adapter.close();
    }
  };
}

// src/adapters/memory/index.ts
function createMemoryAdapter() {
  const sessions = /* @__PURE__ */ new Map();
  const refreshFamilies = /* @__PURE__ */ new Map();
  const revocationList = /* @__PURE__ */ new Map();
  const totpSecrets = /* @__PURE__ */ new Map();
  const backupCodes = /* @__PURE__ */ new Map();
  const oauthLinks = /* @__PURE__ */ new Map();
  return {
    async createSession(session) {
      sessions.set(session.id, { ...session });
      return { ...session };
    },
    async getSession(sessionId) {
      const s = sessions.get(sessionId);
      return s ? { ...s } : null;
    },
    async getSessionsByUser(userId) {
      return [...sessions.values()].filter((s) => s.userId === userId).map((s) => ({ ...s }));
    },
    async updateSession(sessionId, updates) {
      const s = sessions.get(sessionId);
      if (!s) return null;
      const updated = { ...s, ...updates };
      sessions.set(sessionId, updated);
      return { ...updated };
    },
    async deleteSession(sessionId) {
      return sessions.delete(sessionId);
    },
    async deleteSessionsByUser(userId) {
      let count = 0;
      for (const [id, s] of sessions) {
        if (s.userId === userId) {
          sessions.delete(id);
          count++;
        }
      }
      return count;
    },
    async deleteExpiredSessions() {
      const now = /* @__PURE__ */ new Date();
      let count = 0;
      for (const [id, s] of sessions) {
        if (s.expiresAt < now || s.isRevoked) {
          sessions.delete(id);
          count++;
        }
      }
      return count;
    },
    async storeRefreshTokenFamily(family, userId, generation) {
      refreshFamilies.set(family, { userId, generation, revoked: false });
    },
    async getRefreshTokenFamily(family) {
      return refreshFamilies.get(family) ?? null;
    },
    async revokeRefreshTokenFamily(family) {
      const r = refreshFamilies.get(family);
      if (r) r.revoked = true;
    },
    async incrementRefreshTokenGeneration(family) {
      const r = refreshFamilies.get(family);
      if (!r) throw new Error(`Family ${family} not found`);
      r.generation++;
      return r.generation;
    },
    async addToRevocationList(jti, expiresAt) {
      revocationList.set(jti, expiresAt);
    },
    async isRevoked(jti) {
      return revocationList.has(jti);
    },
    async cleanupRevocationList() {
      const now = /* @__PURE__ */ new Date();
      let count = 0;
      for (const [jti, exp] of revocationList) {
        if (exp < now) {
          revocationList.delete(jti);
          count++;
        }
      }
      return count;
    },
    async storeTOTPSecret(userId, secret) {
      totpSecrets.set(userId, secret);
    },
    async getTOTPSecret(userId) {
      return totpSecrets.get(userId) ?? null;
    },
    async removeTOTPSecret(userId) {
      totpSecrets.delete(userId);
      backupCodes.delete(userId);
    },
    async storeBackupCodes(userId, codes) {
      backupCodes.set(userId, [...codes]);
    },
    async getBackupCodes(userId) {
      return backupCodes.get(userId) ?? [];
    },
    async consumeBackupCode(userId, code) {
      const codes = backupCodes.get(userId);
      if (!codes) return false;
      const n = code.toUpperCase();
      const idx = codes.findIndex((c) => c === n);
      if (idx === -1) return false;
      codes.splice(idx, 1);
      return true;
    },
    async linkOAuthAccount(userId, link) {
      const links = oauthLinks.get(userId) ?? [];
      const existing = links.findIndex((l) => l.provider === link.provider);
      if (existing >= 0) links[existing] = link;
      else links.push(link);
      oauthLinks.set(userId, links);
    },
    async getOAuthLinks(userId) {
      return oauthLinks.get(userId) ?? [];
    },
    async findUserByOAuth(provider, providerUserId) {
      for (const [userId, links] of oauthLinks) {
        if (links.some((l) => l.provider === provider && l.providerUserId === providerUserId)) return userId;
      }
      return null;
    },
    async unlinkOAuthAccount(userId, provider) {
      const links = oauthLinks.get(userId);
      if (!links) return false;
      const filtered = links.filter((l) => l.provider !== provider);
      if (filtered.length === links.length) return false;
      oauthLinks.set(userId, filtered);
      return true;
    },
    async initialize() {
    },
    async close() {
      sessions.clear();
      refreshFamilies.clear();
      revocationList.clear();
      totpSecrets.clear();
      backupCodes.clear();
      oauthLinks.clear();
    }
  };
}

exports.AuthErrorCode = AuthErrorCode;
exports.ConfigurationError = ConfigurationError;
exports.EmailError = EmailError;
exports.LockVaultError = LockVaultError;
exports.OAuthError = OAuthError;
exports.RateLimitError = RateLimitError;
exports.RefreshTokenReuseError = RefreshTokenReuseError;
exports.SessionError = SessionError;
exports.TOTPError = TOTPError;
exports.TokenExpiredError = TokenExpiredError;
exports.TokenInvalidError = TokenInvalidError;
exports.TokenRevokedError = TokenRevokedError;
exports.createJWTManager = createJWTManager;
exports.createLockVault = createLockVault;
exports.createMemoryAdapter = createMemoryAdapter;
exports.createMemoryKeyValueStore = createMemoryKeyValueStore;
exports.createOAuthManager = createOAuthManager;
exports.createRateLimiter = createRateLimiter;
exports.createSessionManager = createSessionManager;
exports.createTOTPManager = createTOTPManager;
exports.generateBackupCodes = generateBackupCodes;
exports.generateCSRFToken = generateCSRFToken;
exports.generateId = generateId;
exports.generatePKCE = generatePKCE;
exports.generateTokenFingerprint = generateTokenFingerprint;
exports.generateUUID = generateUUID;
exports.hashPassword = hashPassword;
exports.sanitizeIpAddress = sanitizeIpAddress;
exports.verifyPassword = verifyPassword;
//# sourceMappingURL=index.js.map
//# sourceMappingURL=index.js.map
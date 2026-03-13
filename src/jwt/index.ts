import { createSign, createVerify, createHmac, sign as cryptoSign, verify as cryptoVerify, createHash } from 'node:crypto';
import { TokenPayload, AccessTokenPayload, RefreshTokenPayload, TokenPair, DecodedToken, LockVaultConfig, DatabaseAdapter, LockVaultHooks } from '../types/index.js';
import { generateUUID, encrypt, decrypt, safeCompare } from '../utils/crypto.js';
import { TokenExpiredError, TokenInvalidError, TokenRevokedError, RefreshTokenReuseError, ConfigurationError } from '../utils/errors.js';

function base64UrlEncode(data: string | Buffer): string {
  const buf = typeof data === 'string' ? Buffer.from(data) : data;
  return buf.toString('base64url');
}
function base64UrlDecode(str: string): string {
  return Buffer.from(str, 'base64url').toString('utf8');
}

const ASYMMETRIC_ALGS = new Set(['RS256', 'ES256', 'ES384', 'ES512', 'EdDSA']);

/** Generate a short key ID from a secret for the `kid` header */
function deriveKid(secret: string): string {
  return createHash('sha256').update(secret).digest('base64url').slice(0, 8);
}

export interface JWTManager {
  createTokenPair(userId: string, customClaims?: Record<string, unknown>, sessionId?: string): Promise<TokenPair>;
  verifyAccessToken(token: string): Promise<AccessTokenPayload>;
  verifyRefreshToken(token: string): Promise<RefreshTokenPayload>;
  refreshTokens(refreshToken: string, customClaims?: Record<string, unknown>): Promise<TokenPair>;
  revokeToken(token: string): Promise<void>;
  rotateKeys(newSecret: string): void;
  decode(token: string): DecodedToken;
}

export function createJWTManager(config: LockVaultConfig, hooks: Partial<LockVaultHooks> = {}): JWTManager {
  const adapter: DatabaseAdapter = config.adapter;
  let previousSecrets: Array<{ secret: string; kid: string }> = [];

  // Validate config
  const alg = config.jwt.algorithm ?? 'HS256';
  if (ASYMMETRIC_ALGS.has(alg)) {
    if (!config.jwt.privateKey || !config.jwt.publicKey) throw new ConfigurationError(`privateKey and publicKey are required for ${alg}`);
  } else {
    if (!config.jwt.accessTokenSecret) throw new ConfigurationError(`accessTokenSecret is required for ${alg}`);
    if (config.jwt.accessTokenSecret.length < 32) throw new ConfigurationError(`accessTokenSecret must be at least 32 characters for ${alg}`);
    if (config.jwt.refreshTokenSecret && config.jwt.refreshTokenSecret.length < 32) throw new ConfigurationError(`refreshTokenSecret must be at least 32 characters for ${alg}`);
  }

  // ── Internal sign/verify ────────────────────────────────────────────────

  function signToken(payload: TokenPayload, secret: string): string {
    const algorithm = config.jwt.algorithm ?? 'HS256';
    const kid = ASYMMETRIC_ALGS.has(algorithm) ? undefined : deriveKid(secret);
    const header: Record<string, unknown> = { alg: algorithm, typ: 'JWT' };
    if (kid) header.kid = kid;

    const headerB64 = base64UrlEncode(JSON.stringify(header));
    const payloadB64 = base64UrlEncode(JSON.stringify(payload));
    const signingInput = `${headerB64}.${payloadB64}`;
    const inputBuf = Buffer.from(signingInput);
    let signature: string;
    switch (algorithm) {
      case 'HS256': signature = createHmac('sha256', secret).update(signingInput).digest('base64url'); break;
      case 'RS256': { const s = createSign('RSA-SHA256'); s.update(signingInput); signature = s.sign(config.jwt.privateKey!, 'base64url'); break; }
      case 'ES256': { const s = createSign('SHA256'); s.update(signingInput); signature = s.sign({ key: config.jwt.privateKey!, dsaEncoding: 'ieee-p1363' }, 'base64url'); break; }
      case 'ES384': { const s = createSign('SHA384'); s.update(signingInput); signature = s.sign({ key: config.jwt.privateKey!, dsaEncoding: 'ieee-p1363' }, 'base64url'); break; }
      case 'ES512': { const s = createSign('SHA512'); s.update(signingInput); signature = s.sign({ key: config.jwt.privateKey!, dsaEncoding: 'ieee-p1363' }, 'base64url'); break; }
      case 'EdDSA': { const edSig = cryptoSign(null, inputBuf, config.jwt.privateKey!); signature = edSig.toString('base64url'); break; }
      default: throw new ConfigurationError(`Unsupported algorithm: ${algorithm}`);
    }
    return `${signingInput}.${signature}`;
  }

  function verifySignature(algorithm: string, signingInput: string, signature: string, secret: string, kid?: string): boolean {
    const sigBuf = Buffer.from(signature, 'base64url');
    const inputBuf = Buffer.from(signingInput);
    switch (algorithm) {
      case 'HS256': {
        // If kid is present, try to find the matching key first for efficiency
        const allSecrets = kid
          ? [
              ...(deriveKid(secret) === kid ? [secret] : []),
              ...previousSecrets.filter(s => s.kid === kid).map(s => s.secret),
              // Fallback: try all if kid didn't match (handles legacy tokens)
              ...(deriveKid(secret) !== kid ? [secret] : []),
              ...previousSecrets.filter(s => s.kid !== kid).map(s => s.secret),
            ]
          : [secret, ...previousSecrets.map(s => s.secret)];

        for (const s of allSecrets) {
          const expected = createHmac('sha256', s).update(signingInput).digest('base64url');
          if (safeCompare(expected, signature)) return true;
        }
        return false;
      }
      case 'RS256': { const v = createVerify('RSA-SHA256'); v.update(signingInput); return v.verify(config.jwt.publicKey!, sigBuf); }
      case 'ES256': { const v = createVerify('SHA256'); v.update(signingInput); return v.verify({ key: config.jwt.publicKey!, dsaEncoding: 'ieee-p1363' }, sigBuf); }
      case 'ES384': { const v = createVerify('SHA384'); v.update(signingInput); return v.verify({ key: config.jwt.publicKey!, dsaEncoding: 'ieee-p1363' }, sigBuf); }
      case 'ES512': { const v = createVerify('SHA512'); v.update(signingInput); return v.verify({ key: config.jwt.publicKey!, dsaEncoding: 'ieee-p1363' }, sigBuf); }
      case 'EdDSA': return cryptoVerify(null, inputBuf, config.jwt.publicKey!, sigBuf);
      default: return false;
    }
  }

  function verifyToken(token: string, secret: string): TokenPayload {
    const parts = token.split('.');
    if (parts.length !== 3) throw new TokenInvalidError('Token must have 3 parts');
    const [headerB64, payloadB64, signature] = parts as [string, string, string];
    const signingInput = `${headerB64}.${payloadB64}`;
    const algorithm = config.jwt.algorithm ?? 'HS256';

    let header: Record<string, unknown>;
    try { header = JSON.parse(base64UrlDecode(headerB64)); } catch { throw new TokenInvalidError('Malformed token header'); }
    if (header.alg !== algorithm) throw new TokenInvalidError(`Algorithm mismatch: expected "${algorithm}"`);

    if (!verifySignature(algorithm, signingInput, signature, secret, header.kid as string | undefined)) {
      throw new TokenInvalidError('Invalid signature');
    }

    const payload = JSON.parse(base64UrlDecode(payloadB64)) as TokenPayload;
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) throw new TokenExpiredError();
    if (payload.nbf && payload.nbf > now) throw new TokenInvalidError('Token is not yet valid');

    const expectedIssuer = config.jwt.issuer;
    if (expectedIssuer && payload.iss !== expectedIssuer) throw new TokenInvalidError('Issuer mismatch');
    const expectedAudience = config.jwt.audience;
    if (expectedAudience) {
      const tokenAud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
      if (!tokenAud.includes(expectedAudience)) throw new TokenInvalidError('Audience mismatch');
    }
    return payload;
  }

  // ── Public API ──────────────────────────────────────────────────────────

  return {
    async createTokenPair(userId, customClaims = {}, sessionId?) {
      const now = Math.floor(Date.now() / 1000);
      const jwtConfig = config.jwt;
      const accessTTL = jwtConfig.accessTokenTTL ?? 900;
      const refreshTTL = jwtConfig.refreshTokenTTL ?? 604800;
      let claims = { ...customClaims };
      if (hooks.beforeTokenCreate) claims = await hooks.beforeTokenCreate(claims);

      const accessJti = generateUUID(); const refreshJti = generateUUID(); const family = generateUUID();
      const accessPayload: AccessTokenPayload = {
        sub: userId, iat: now, nbf: now, exp: now + accessTTL, jti: accessJti, type: 'access',
        ...(jwtConfig.issuer ? { iss: jwtConfig.issuer } : {}),
        ...(jwtConfig.audience ? { aud: jwtConfig.audience } : {}),
        ...(sessionId ? { sid: sessionId } : {}),
        ...claims,
      };
      const refreshPayload: RefreshTokenPayload = {
        sub: userId, iat: now, nbf: now, exp: now + refreshTTL, jti: refreshJti, type: 'refresh',
        family, generation: 0,
        ...(jwtConfig.issuer ? { iss: jwtConfig.issuer } : {}),
        ...(sessionId ? { sid: sessionId } : {}),
      };

      const accessToken = signToken(accessPayload, jwtConfig.accessTokenSecret);
      let refreshToken = signToken(refreshPayload, jwtConfig.refreshTokenSecret ?? jwtConfig.accessTokenSecret);
      const encConfig = config.refreshToken?.encryption;
      if (encConfig?.enabled) refreshToken = encrypt(refreshToken, encConfig.key);
      await adapter.storeRefreshTokenFamily(family, userId, 0);

      const tokenPair: TokenPair = {
        accessToken, refreshToken,
        accessTokenExpiresAt: new Date((now + accessTTL) * 1000),
        refreshTokenExpiresAt: new Date((now + refreshTTL) * 1000),
      };
      if (hooks.afterTokenCreate) await hooks.afterTokenCreate(tokenPair);
      return tokenPair;
    },

    async verifyAccessToken(token) {
      let processedToken = token;
      if (hooks.beforeTokenVerify) processedToken = await hooks.beforeTokenVerify(processedToken);
      const payload = verifyToken(processedToken, config.jwt.accessTokenSecret) as AccessTokenPayload;
      if (payload.type !== 'access') throw new TokenInvalidError('Expected access token');
      if (await adapter.isRevoked(payload.jti)) throw new TokenRevokedError();
      if (hooks.afterTokenVerify) await hooks.afterTokenVerify(payload);
      return payload;
    },

    async verifyRefreshToken(token) {
      let processedToken = token;
      const encConfig = config.refreshToken?.encryption;
      if (encConfig?.enabled) processedToken = decrypt(processedToken, encConfig.key);
      const secret = config.jwt.refreshTokenSecret ?? config.jwt.accessTokenSecret;
      const payload = verifyToken(processedToken, secret) as RefreshTokenPayload;
      if (payload.type !== 'refresh') throw new TokenInvalidError('Expected refresh token');
      return payload;
    },

    async refreshTokens(refreshToken, customClaims = {}) {
      const payload = await this.verifyRefreshToken(refreshToken);
      const { family, generation, sub: userId } = payload;
      const familyRecord = await adapter.getRefreshTokenFamily(family);
      if (!familyRecord) throw new TokenInvalidError('Unknown refresh token family');
      if (familyRecord.revoked) throw new TokenRevokedError('Refresh token family has been revoked');

      const reuseConfig = config.refreshToken;
      if (reuseConfig?.reuseDetection !== false && generation < familyRecord.generation) {
        if (reuseConfig?.familyRevocationOnReuse !== false) {
          await adapter.revokeRefreshTokenFamily(family);
          await adapter.deleteSessionsByUser(userId);
        }
        if (hooks.onReuseDetected) await hooks.onReuseDetected(family, userId);
        throw new RefreshTokenReuseError(family);
      }

      const now = Math.floor(Date.now() / 1000);
      const jwtConfig = config.jwt;
      const accessTTL = jwtConfig.accessTokenTTL ?? 900;
      const refreshTTL = jwtConfig.refreshTokenTTL ?? 604800;
      let claims = { ...customClaims };
      if (hooks.beforeTokenCreate) claims = await hooks.beforeTokenCreate(claims);
      const newGeneration = await adapter.incrementRefreshTokenGeneration(family);
      const accessJti = generateUUID(); const refreshJti = generateUUID();

      const accessPayload: AccessTokenPayload = {
        sub: userId, iat: now, nbf: now, exp: now + accessTTL, jti: accessJti, type: 'access',
        ...(jwtConfig.issuer ? { iss: jwtConfig.issuer } : {}),
        ...(jwtConfig.audience ? { aud: jwtConfig.audience } : {}),
        ...(payload.sid ? { sid: payload.sid } : {}),
        ...claims,
      };
      const refreshPayload: RefreshTokenPayload = {
        sub: userId, iat: now, nbf: now, exp: now + refreshTTL, jti: refreshJti, type: 'refresh',
        family, generation: newGeneration,
        ...(jwtConfig.issuer ? { iss: jwtConfig.issuer } : {}),
        ...(payload.sid ? { sid: payload.sid } : {}),
      };

      const newAccessToken = signToken(accessPayload, jwtConfig.accessTokenSecret);
      let newRefreshToken = signToken(refreshPayload, jwtConfig.refreshTokenSecret ?? jwtConfig.accessTokenSecret);
      const encConfig = config.refreshToken?.encryption;
      if (encConfig?.enabled) newRefreshToken = encrypt(newRefreshToken, encConfig.key);

      const tokenPair: TokenPair = {
        accessToken: newAccessToken, refreshToken: newRefreshToken,
        accessTokenExpiresAt: new Date((now + accessTTL) * 1000),
        refreshTokenExpiresAt: new Date((now + refreshTTL) * 1000),
      };
      if (hooks.afterTokenCreate) await hooks.afterTokenCreate(tokenPair);
      return tokenPair;
    },

    async revokeToken(token) {
      const parts = token.split('.');
      if (parts.length !== 3) throw new TokenInvalidError('Cannot revoke: token is malformed');
      const [headerB64, payloadB64, signature] = parts as [string, string, string];
      const signingInput = `${headerB64}.${payloadB64}`;
      const algorithm = config.jwt.algorithm ?? 'HS256';

      let header: Record<string, unknown>;
      try { header = JSON.parse(base64UrlDecode(headerB64)); } catch { throw new TokenInvalidError('Cannot revoke: token is malformed'); }
      if (header.alg !== algorithm) throw new TokenInvalidError('Cannot revoke: algorithm mismatch');

      let payload: TokenPayload;
      try { payload = JSON.parse(base64UrlDecode(payloadB64)) as TokenPayload; } catch { throw new TokenInvalidError('Cannot revoke: token is malformed'); }

      const secret = payload.type === 'refresh' ? (config.jwt.refreshTokenSecret ?? config.jwt.accessTokenSecret) : config.jwt.accessTokenSecret;
      if (!verifySignature(algorithm, signingInput, signature, secret, header.kid as string | undefined)) {
        throw new TokenInvalidError('Cannot revoke: invalid signature');
      }

      await adapter.addToRevocationList(payload.jti, new Date(payload.exp * 1000));
      if (payload.type === 'refresh') {
        const rp = payload as RefreshTokenPayload;
        await adapter.revokeRefreshTokenFamily(rp.family);
      }
      if (hooks.onTokenRevoked) await hooks.onTokenRevoked(payload.jti);
    },

    rotateKeys(newSecret: string) {
      if (newSecret.length < 32) throw new ConfigurationError('New secret must be at least 32 characters');
      previousSecrets.push({ secret: config.jwt.accessTokenSecret, kid: deriveKid(config.jwt.accessTokenSecret) });
      config.jwt.accessTokenSecret = newSecret;
      // Keep last 3 rotated keys for grace period
      if (previousSecrets.length > 3) previousSecrets.shift();
    },

    decode(token: string): DecodedToken {
      const parts = token.split('.');
      if (parts.length !== 3) throw new TokenInvalidError('Token must have 3 parts');
      try {
        const header = JSON.parse(base64UrlDecode(parts[0]!));
        const payload = JSON.parse(base64UrlDecode(parts[1]!));
        return { header, payload, signature: parts[2]! };
      } catch { throw new TokenInvalidError('Failed to decode token'); }
    },
  };
}

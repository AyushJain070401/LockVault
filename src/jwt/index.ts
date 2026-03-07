import { createSign, createVerify, createHmac, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';
import {

  TokenPayload,
  AccessTokenPayload,
  RefreshTokenPayload,
  TokenPair,
  DecodedToken,
  LockVaultConfig,
  DatabaseAdapter,
  LockVaultHooks,
} from '../types/index.js';
import { generateUUID, encrypt, decrypt, safeCompare } from '../utils/crypto.js';
import {
  TokenExpiredError,
  TokenInvalidError,
  TokenRevokedError,
  RefreshTokenReuseError,
  ConfigurationError,
} from '../utils/errors.js';

function base64UrlEncode(data: string | Buffer): string {
  const buf = typeof data === 'string' ? Buffer.from(data) : data;
  return buf.toString('base64url');
}

function base64UrlDecode(str: string): string {
  return Buffer.from(str, 'base64url').toString('utf8');
}

export class JWTManager {
  private readonly config: LockVaultConfig;
  private readonly adapter: DatabaseAdapter;
  private readonly hooks: Partial<LockVaultHooks>;

  // Key rotation support
  private previousSecrets: string[] = [];

  constructor(config: LockVaultConfig, hooks: Partial<LockVaultHooks> = {}) {
    this.config = config;
    this.adapter = config.adapter;
    this.hooks = hooks;
    this.validateConfig();
  }

  private static readonly ASYMMETRIC_ALGS = new Set(['RS256', 'ES256', 'ES384', 'ES512', 'EdDSA']);

  private validateConfig(): void {
    const { jwt } = this.config;
    const alg = jwt.algorithm ?? 'HS256';

    if (JWTManager.ASYMMETRIC_ALGS.has(alg)) {
      // Asymmetric algorithms require key pair
      if (!jwt.privateKey || !jwt.publicKey) {
        throw new ConfigurationError(`privateKey and publicKey are required for ${alg}`);
      }
    } else {
      // Symmetric algorithms require secret
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

  async createTokenPair(
    userId: string,
    customClaims: Record<string, unknown> = {},
    sessionId?: string,
  ): Promise<TokenPair> {
    const now = Math.floor(Date.now() / 1000);
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

    const accessPayload: AccessTokenPayload = {
      sub: userId,
      iat: now,
      nbf: now,
      exp: now + accessTTL,
      jti: accessJti,
      type: 'access',
      ...(jwtConfig.issuer ? { iss: jwtConfig.issuer } : {}),
      ...(jwtConfig.audience ? { aud: jwtConfig.audience } : {}),
      ...(sessionId ? { sid: sessionId } : {}),
      ...claims,
    };

    const refreshPayload: RefreshTokenPayload = {
      sub: userId,
      iat: now,
      nbf: now,
      exp: now + refreshTTL,
      jti: refreshJti,
      type: 'refresh',
      family,
      generation: 0,
      ...(jwtConfig.issuer ? { iss: jwtConfig.issuer } : {}),
      ...(sessionId ? { sid: sessionId } : {}),
    };

    const accessToken = this.sign(accessPayload, jwtConfig.accessTokenSecret);
    let refreshToken = this.sign(
      refreshPayload,
      jwtConfig.refreshTokenSecret ?? jwtConfig.accessTokenSecret,
    );

    // Optionally encrypt the refresh token
    const encConfig = this.config.refreshToken?.encryption;
    if (encConfig?.enabled) {
      refreshToken = encrypt(refreshToken, encConfig.key);
    }

    // Store refresh token family for rotation tracking
    await this.adapter.storeRefreshTokenFamily(family, userId, 0);

    const tokenPair: TokenPair = {
      accessToken,
      refreshToken,
      accessTokenExpiresAt: new Date((now + accessTTL) * 1000),
      refreshTokenExpiresAt: new Date((now + refreshTTL) * 1000),
    };

    if (this.hooks.afterTokenCreate) {
      await this.hooks.afterTokenCreate(tokenPair);
    }

    return tokenPair;
  }

  // ─── Token Verification ─────────────────────────────────────────────────

  async verifyAccessToken(token: string): Promise<AccessTokenPayload> {
    let processedToken = token;
    if (this.hooks.beforeTokenVerify) {
      processedToken = await this.hooks.beforeTokenVerify(processedToken);
    }

    const payload = this.verify(processedToken, this.config.jwt.accessTokenSecret) as AccessTokenPayload;

    if (payload.type !== 'access') {
      throw new TokenInvalidError('Expected access token');
    }

    // Check revocation list
    if (await this.adapter.isRevoked(payload.jti)) {
      throw new TokenRevokedError();
    }

    if (this.hooks.afterTokenVerify) {
      await this.hooks.afterTokenVerify(payload);
    }

    return payload;
  }

  async verifyRefreshToken(token: string): Promise<RefreshTokenPayload> {
    let processedToken = token;

    // Decrypt if encrypted
    const encConfig = this.config.refreshToken?.encryption;
    if (encConfig?.enabled) {
      processedToken = decrypt(processedToken, encConfig.key);
    }

    const secret = this.config.jwt.refreshTokenSecret ?? this.config.jwt.accessTokenSecret;
    const payload = this.verify(processedToken, secret) as RefreshTokenPayload;

    if (payload.type !== 'refresh') {
      throw new TokenInvalidError('Expected refresh token');
    }

    return payload;
  }

  // ─── Token Refresh with Rotation ────────────────────────────────────────

  async refreshTokens(
    refreshToken: string,
    customClaims: Record<string, unknown> = {},
  ): Promise<TokenPair> {
    const payload = await this.verifyRefreshToken(refreshToken);
    const { family, generation, sub: userId } = payload;

    // Check family status
    const familyRecord = await this.adapter.getRefreshTokenFamily(family);

    if (!familyRecord) {
      throw new TokenInvalidError('Unknown refresh token family');
    }

    if (familyRecord.revoked) {
      throw new TokenRevokedError('Refresh token family has been revoked');
    }

    // Reuse detection: if the token's generation doesn't match current, it's reuse
    const reuseConfig = this.config.refreshToken;
    if (reuseConfig?.reuseDetection !== false && generation < familyRecord.generation) {
      // Token reuse detected!
      if (reuseConfig?.familyRevocationOnReuse !== false) {
        await this.adapter.revokeRefreshTokenFamily(family);

        // Revoke all sessions for this user as a safety measure
        await this.adapter.deleteSessionsByUser(userId);
      }

      if (this.hooks.onReuseDetected) {
        await this.hooks.onReuseDetected(family, userId);
      }

      throw new RefreshTokenReuseError(family);
    }

    // Rotation: issue new tokens with incremented generation
    const now = Math.floor(Date.now() / 1000);
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

    const accessPayload: AccessTokenPayload = {
      sub: userId,
      iat: now,
      nbf: now,
      exp: now + accessTTL,
      jti: accessJti,
      type: 'access',
      ...(jwtConfig.issuer ? { iss: jwtConfig.issuer } : {}),
      ...(jwtConfig.audience ? { aud: jwtConfig.audience } : {}),
      ...(payload.sid ? { sid: payload.sid } : {}),
      ...claims,
    };

    const refreshPayload: RefreshTokenPayload = {
      sub: userId,
      iat: now,
      nbf: now,
      exp: now + refreshTTL,
      jti: refreshJti,
      type: 'refresh',
      family,
      generation: newGeneration,
      ...(jwtConfig.issuer ? { iss: jwtConfig.issuer } : {}),
      ...(payload.sid ? { sid: payload.sid } : {}),
    };

    const newAccessToken = this.sign(accessPayload, jwtConfig.accessTokenSecret);
    let newRefreshToken = this.sign(
      refreshPayload,
      jwtConfig.refreshTokenSecret ?? jwtConfig.accessTokenSecret,
    );

    const encConfig = this.config.refreshToken?.encryption;
    if (encConfig?.enabled) {
      newRefreshToken = encrypt(newRefreshToken, encConfig.key);
    }

    const tokenPair: TokenPair = {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      accessTokenExpiresAt: new Date((now + accessTTL) * 1000),
      refreshTokenExpiresAt: new Date((now + refreshTTL) * 1000),
    };

    if (this.hooks.afterTokenCreate) {
      await this.hooks.afterTokenCreate(tokenPair);
    }

    return tokenPair;
  }

  // ─── Token Revocation ───────────────────────────────────────────────────

  async revokeToken(token: string): Promise<void> {
    // Verify signature to prevent attackers from crafting fake tokens
    // to poison the revocation list or revoke arbitrary families.
    // We decode manually and verify the signature, but allow expired tokens
    // (a user logging out with a recently expired token is a valid use case).
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new TokenInvalidError('Cannot revoke: token is malformed');
    }

    const [headerB64, payloadB64, signature] = parts as [string, string, string];
    const signingInput = `${headerB64}.${payloadB64}`;
    const algorithm = this.config.jwt.algorithm ?? 'HS256';

    // Verify header algorithm
    let header: Record<string, unknown>;
    try {
      header = JSON.parse(base64UrlDecode(headerB64));
    } catch {
      throw new TokenInvalidError('Cannot revoke: token is malformed');
    }
    if (header.alg !== algorithm) {
      throw new TokenInvalidError('Cannot revoke: algorithm mismatch');
    }

    // Verify signature (try current + previous secrets)
    let payload: TokenPayload;
    try {
      payload = JSON.parse(base64UrlDecode(payloadB64)) as TokenPayload;
    } catch {
      throw new TokenInvalidError('Cannot revoke: token is malformed');
    }

    const secret = payload.type === 'refresh'
      ? (this.config.jwt.refreshTokenSecret ?? this.config.jwt.accessTokenSecret)
      : this.config.jwt.accessTokenSecret;
    const verified = this.verifySignature(algorithm, signingInput, signature, secret);

    if (!verified) {
      throw new TokenInvalidError('Cannot revoke: invalid signature');
    }

    // Signature is valid — safe to trust the payload
    await this.adapter.addToRevocationList(payload.jti, new Date(payload.exp * 1000));

    if (payload.type === 'refresh') {
      const refreshPayload = payload as RefreshTokenPayload;
      await this.adapter.revokeRefreshTokenFamily(refreshPayload.family);
    }

    if (this.hooks.onTokenRevoked) {
      await this.hooks.onTokenRevoked(payload.jti);
    }
  }

  // ─── Key Rotation ──────────────────────────────────────────────────────

  rotateKeys(newSecret: string): void {
    this.previousSecrets.push(this.config.jwt.accessTokenSecret);
    this.config.jwt.accessTokenSecret = newSecret;
    // Keep only last 3 secrets for verification
    if (this.previousSecrets.length > 3) {
      this.previousSecrets.shift();
    }
  }

  // ─── Decode (without verification) ──────────────────────────────────────

  decode(token: string): DecodedToken {
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new TokenInvalidError('Token must have 3 parts');
    }
    try {
      const header = JSON.parse(base64UrlDecode(parts[0]!));
      const payload = JSON.parse(base64UrlDecode(parts[1]!));
      return { header, payload, signature: parts[2]! };
    } catch {
      throw new TokenInvalidError('Failed to decode token');
    }
  }

  // ─── Low-level Sign / Verify ────────────────────────────────────────────

  private sign(payload: TokenPayload, secret: string): string {
    const algorithm = this.config.jwt.algorithm ?? 'HS256';
    const header = { alg: algorithm, typ: 'JWT' };
    const headerB64 = base64UrlEncode(JSON.stringify(header));
    const payloadB64 = base64UrlEncode(JSON.stringify(payload));
    const signingInput = `${headerB64}.${payloadB64}`;
    const inputBuf = Buffer.from(signingInput);

    let signature: string;

    switch (algorithm) {
      case 'HS256':
        signature = createHmac('sha256', secret).update(signingInput).digest('base64url');
        break;

      case 'RS256': {
        const rsaSigner = createSign('RSA-SHA256');
        rsaSigner.update(signingInput);
        signature = rsaSigner.sign(this.config.jwt.privateKey!, 'base64url');
        break;
      }

      case 'ES256': {
        const es256Signer = createSign('SHA256');
        es256Signer.update(signingInput);
        signature = es256Signer.sign(
          { key: this.config.jwt.privateKey!, dsaEncoding: 'ieee-p1363' },
          'base64url',
        );
        break;
      }

      case 'ES384': {
        const es384Signer = createSign('SHA384');
        es384Signer.update(signingInput);
        signature = es384Signer.sign(
          { key: this.config.jwt.privateKey!, dsaEncoding: 'ieee-p1363' },
          'base64url',
        );
        break;
      }

      case 'ES512': {
        const es512Signer = createSign('SHA512');
        es512Signer.update(signingInput);
        signature = es512Signer.sign(
          { key: this.config.jwt.privateKey!, dsaEncoding: 'ieee-p1363' },
          'base64url',
        );
        break;
      }

      case 'EdDSA': {
        const edSig = cryptoSign(null, inputBuf, this.config.jwt.privateKey!);
        signature = edSig.toString('base64url');
        break;
      }

      default:
        throw new ConfigurationError(`Unsupported algorithm: ${algorithm}`);
    }

    return `${signingInput}.${signature}`;
  }

  private verify(token: string, secret: string): TokenPayload {
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new TokenInvalidError('Token must have 3 parts');
    }

    const [headerB64, payloadB64, signature] = parts as [string, string, string];
    const signingInput = `${headerB64}.${payloadB64}`;
    const algorithm = this.config.jwt.algorithm ?? 'HS256';

    // ── Algorithm enforcement: reject tokens claiming a different algorithm ──
    let header: Record<string, unknown>;
    try {
      header = JSON.parse(base64UrlDecode(headerB64));
    } catch {
      throw new TokenInvalidError('Malformed token header');
    }
    if (header.alg !== algorithm) {
      throw new TokenInvalidError(
        `Algorithm mismatch: token uses "${header.alg}" but server requires "${algorithm}"`,
      );
    }

    // ── Signature verification ──
    const verified = this.verifySignature(algorithm, signingInput, signature, secret);

    if (!verified) {
      throw new TokenInvalidError('Invalid signature');
    }

    const payload = JSON.parse(base64UrlDecode(payloadB64)) as TokenPayload;
    const now = Math.floor(Date.now() / 1000);

    if (payload.exp && payload.exp < now) {
      throw new TokenExpiredError();
    }

    if (payload.nbf && payload.nbf > now) {
      throw new TokenInvalidError('Token is not yet valid');
    }

    // ── Issuer validation ──
    const expectedIssuer = this.config.jwt.issuer;
    if (expectedIssuer && payload.iss !== expectedIssuer) {
      throw new TokenInvalidError(
        `Issuer mismatch: expected "${expectedIssuer}" but got "${payload.iss}"`,
      );
    }

    // ── Audience validation ──
    const expectedAudience = this.config.jwt.audience;
    if (expectedAudience) {
      const tokenAud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
      if (!tokenAud.includes(expectedAudience)) {
        throw new TokenInvalidError(
          `Audience mismatch: expected "${expectedAudience}"`,
        );
      }
    }

    return payload;
  }

  // ─── Shared Signature Verification ──────────────────────────────────────

  private verifySignature(
    algorithm: string,
    signingInput: string,
    signature: string,
    secret: string,
  ): boolean {
    const sigBuf = Buffer.from(signature, 'base64url');
    const inputBuf = Buffer.from(signingInput);

    switch (algorithm) {
      case 'HS256': {
        const secrets = [secret, ...this.previousSecrets];
        for (const s of secrets) {
          const expected = createHmac('sha256', s).update(signingInput).digest('base64url');
          if (safeCompare(expected, signature)) return true;
        }
        return false;
      }

      case 'RS256': {
        const rsaV = createVerify('RSA-SHA256');
        rsaV.update(signingInput);
        return rsaV.verify(this.config.jwt.publicKey!, sigBuf);
      }

      case 'ES256': {
        const es256V = createVerify('SHA256');
        es256V.update(signingInput);
        return es256V.verify({ key: this.config.jwt.publicKey!, dsaEncoding: 'ieee-p1363' }, sigBuf);
      }

      case 'ES384': {
        const es384V = createVerify('SHA384');
        es384V.update(signingInput);
        return es384V.verify({ key: this.config.jwt.publicKey!, dsaEncoding: 'ieee-p1363' }, sigBuf);
      }

      case 'ES512': {
        const es512V = createVerify('SHA512');
        es512V.update(signingInput);
        return es512V.verify({ key: this.config.jwt.publicKey!, dsaEncoding: 'ieee-p1363' }, sigBuf);
      }

      case 'EdDSA':
        return cryptoVerify(null, inputBuf, this.config.jwt.publicKey!, sigBuf);

      default:
        return false;
    }
  }
}

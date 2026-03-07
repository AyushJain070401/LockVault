import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JWTManager } from '../../src/jwt/index.js';
import { MemoryAdapter } from '../../src/adapters/memory/index.js';
import { TokenExpiredError, TokenInvalidError, TokenRevokedError, RefreshTokenReuseError } from '../../src/utils/errors.js';
import type { LockVaultConfig } from '../../src/types/index.js';

function createConfig(overrides: Partial<LockVaultConfig['jwt']> = {}): LockVaultConfig {
  return {
    jwt: {
      accessTokenSecret: 'test-secret-access-token-min-length-32chars!',
      refreshTokenSecret: 'test-secret-refresh-token-min-length-32chars!',
      accessTokenTTL: 900,
      refreshTokenTTL: 604800,
      issuer: 'test',
      ...overrides,
    },
    refreshToken: {
      rotation: true,
      reuseDetection: true,
      familyRevocationOnReuse: true,
    },
    adapter: new MemoryAdapter(),
  };
}

describe('JWTManager', () => {
  let jwt: JWTManager;
  let config: LockVaultConfig;

  beforeEach(() => {
    config = createConfig();
    jwt = new JWTManager(config);
  });

  describe('createTokenPair', () => {
    it('should create an access token and refresh token', async () => {
      const pair = await jwt.createTokenPair('user-123');

      expect(pair.accessToken).toBeDefined();
      expect(pair.refreshToken).toBeDefined();
      expect(pair.accessTokenExpiresAt).toBeInstanceOf(Date);
      expect(pair.refreshTokenExpiresAt).toBeInstanceOf(Date);
      expect(pair.accessTokenExpiresAt.getTime()).toBeGreaterThan(Date.now());
      expect(pair.refreshTokenExpiresAt.getTime()).toBeGreaterThan(Date.now());
    });

    it('should include custom claims in the access token', async () => {
      const pair = await jwt.createTokenPair('user-123', { roles: ['admin'], org: 'acme' });
      const payload = await jwt.verifyAccessToken(pair.accessToken);

      expect(payload.sub).toBe('user-123');
      expect(payload.roles).toEqual(['admin']);
      expect(payload.org).toBe('acme');
    });

    it('should include issuer when configured', async () => {
      const pair = await jwt.createTokenPair('user-123');
      const payload = await jwt.verifyAccessToken(pair.accessToken);

      expect(payload.iss).toBe('test');
    });

    it('should create tokens with different JTIs', async () => {
      const pair1 = await jwt.createTokenPair('user-123');
      const pair2 = await jwt.createTokenPair('user-123');

      const decoded1 = jwt.decode(pair1.accessToken);
      const decoded2 = jwt.decode(pair2.accessToken);
      expect(decoded1.payload.jti).not.toBe(decoded2.payload.jti);
    });
  });

  describe('verifyAccessToken', () => {
    it('should verify a valid access token', async () => {
      const pair = await jwt.createTokenPair('user-456');
      const payload = await jwt.verifyAccessToken(pair.accessToken);

      expect(payload.sub).toBe('user-456');
      expect(payload.type).toBe('access');
    });

    it('should reject an expired token', async () => {
      const expiredConfig = createConfig({ accessTokenTTL: -1 });
      const expiredJwt = new JWTManager(expiredConfig);
      const pair = await expiredJwt.createTokenPair('user-123');

      await expect(expiredJwt.verifyAccessToken(pair.accessToken))
        .rejects.toThrow("Token has expired");
    });

    it('should reject a token with invalid signature', async () => {
      const pair = await jwt.createTokenPair('user-123');
      const tampered = pair.accessToken.slice(0, -5) + 'XXXXX';

      await expect(jwt.verifyAccessToken(tampered))
        .rejects.toThrow('Invalid signature');
    });

    it('should reject a refresh token used as access token', async () => {
      const pair = await jwt.createTokenPair('user-123');

      await expect(jwt.verifyAccessToken(pair.refreshToken))
        .rejects.toThrow();
    });

    it('should reject a revoked token', async () => {
      const pair = await jwt.createTokenPair('user-123');
      await jwt.revokeToken(pair.accessToken);

      await expect(jwt.verifyAccessToken(pair.accessToken))
        .rejects.toThrow(/revoked/);
    });
  });

  describe('refreshTokens (rotation)', () => {
    it('should issue new tokens with incremented generation', async () => {
      const original = await jwt.createTokenPair('user-123');
      const refreshed = await jwt.refreshTokens(original.refreshToken);

      expect(refreshed.accessToken).not.toBe(original.accessToken);
      expect(refreshed.refreshToken).not.toBe(original.refreshToken);

      // New access token should be valid
      const payload = await jwt.verifyAccessToken(refreshed.accessToken);
      expect(payload.sub).toBe('user-123');
    });

    it('should detect token reuse after rotation', async () => {
      const original = await jwt.createTokenPair('user-123');

      // First refresh is fine
      await jwt.refreshTokens(original.refreshToken);

      // Reusing the original refresh token should fail
      await expect(jwt.refreshTokens(original.refreshToken))
        .rejects.toThrow(/reuse detected/);
    });

    it('should chain multiple refreshes correctly', async () => {
      let tokens = await jwt.createTokenPair('user-123');

      for (let i = 0; i < 5; i++) {
        const refreshed = await jwt.refreshTokens(tokens.refreshToken);
        const payload = await jwt.verifyAccessToken(refreshed.accessToken);
        expect(payload.sub).toBe('user-123');
        tokens = refreshed;
      }
    });
  });

  describe('token revocation', () => {
    it('should revoke an access token', async () => {
      const pair = await jwt.createTokenPair('user-123');
      await jwt.revokeToken(pair.accessToken);

      await expect(jwt.verifyAccessToken(pair.accessToken))
        .rejects.toThrow(/revoked/);
    });

    it('should revoke entire refresh token family', async () => {
      const pair = await jwt.createTokenPair('user-123');
      await jwt.revokeToken(pair.refreshToken);

      await expect(jwt.refreshTokens(pair.refreshToken))
        .rejects.toThrow();
    });
  });

  describe('decode', () => {
    it('should decode a token without verification', async () => {
      const pair = await jwt.createTokenPair('user-123');
      const decoded = jwt.decode(pair.accessToken);

      expect(decoded.header.alg).toBe('HS256');
      expect(decoded.header.typ).toBe('JWT');
      expect(decoded.payload.sub).toBe('user-123');
    });

    it('should throw on malformed token', () => {
      expect(() => jwt.decode('not.a.valid.token.here')).toThrow(/Token must have 3|Failed to decode/);
      expect(() => jwt.decode('single-part')).toThrow(/Token must have 3|Failed to decode/);
    });
  });

  describe('key rotation', () => {
    it('should accept tokens signed with previous key after rotation', async () => {
      const pair = await jwt.createTokenPair('user-123');

      jwt.rotateKeys('new-secret-that-is-at-least-32chars!');

      // Old token should still verify
      const payload = await jwt.verifyAccessToken(pair.accessToken);
      expect(payload.sub).toBe('user-123');

      // New tokens use new key
      const newPair = await jwt.createTokenPair('user-456');
      const newPayload = await jwt.verifyAccessToken(newPair.accessToken);
      expect(newPayload.sub).toBe('user-456');
    });
  });

  describe('plugin hooks', () => {
    it('should call beforeTokenCreate hook', async () => {
      const hook = vi.fn((claims) => ({ ...claims, injected: true }));
      const hookJwt = new JWTManager(config, { beforeTokenCreate: hook });

      const pair = await hookJwt.createTokenPair('user-123');
      const payload = await hookJwt.verifyAccessToken(pair.accessToken);

      expect(hook).toHaveBeenCalled();
      expect(payload.injected).toBe(true);
    });

    it('should call afterTokenCreate hook', async () => {
      const hook = vi.fn();
      const hookJwt = new JWTManager(config, { afterTokenCreate: hook });

      await hookJwt.createTokenPair('user-123');
      expect(hook).toHaveBeenCalledTimes(1);
    });
  });
});

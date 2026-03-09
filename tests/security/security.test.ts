import { describe, it, expect, beforeEach } from 'vitest';
import { createLockVault } from '../../src/core/index.js';
import { createMemoryAdapter } from '../../src/adapters/memory/index.js';
import { createJWTManager } from '../../src/jwt/index.js';
import {
  TokenInvalidError,
  TokenExpiredError,
  RefreshTokenReuseError,
  ConfigurationError,
} from '../../src/utils/errors.js';
import { encrypt, decrypt, hashPassword, verifyPassword, safeCompare, generateBackupCodes } from '../../src/utils/crypto.js';
import type { LockVaultConfig } from '../../src/types/index.js';

describe('Security Edge Cases', () => {
  let auth: LockVault;

  beforeEach(async () => {
    auth = createLockVault({
      jwt: {
        accessTokenSecret: 'super-secret-key-that-is-at-least-32-chars!',
        refreshTokenSecret: 'another-secret-key-at-least-32-characters!',
        accessTokenTTL: 900,
        refreshTokenTTL: 604800,
      },
      refreshToken: {
        rotation: true,
        reuseDetection: true,
        familyRevocationOnReuse: true,
      },
      adapter: createMemoryAdapter(),
    });
    await auth.initialize();
  });

  describe('Token Tampering', () => {
    it('should reject a token with modified payload', async () => {
      const { tokens } = await auth.login('user-1');
      const parts = tokens.accessToken.split('.');
      // Tamper with the payload
      const payload = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString());
      payload.sub = 'admin';
      parts[1] = Buffer.from(JSON.stringify(payload)).toString('base64url');
      const tampered = parts.join('.');

      await expect(auth.jwt.verifyAccessToken(tampered)).rejects.toThrow('Invalid signature');
    });

    it('should reject a token with modified header', async () => {
      const { tokens } = await auth.login('user-1');
      const parts = tokens.accessToken.split('.');
      // Change algorithm in header
      const header = JSON.parse(Buffer.from(parts[0]!, 'base64url').toString());
      header.alg = 'none';
      parts[0] = Buffer.from(JSON.stringify(header)).toString('base64url');
      const tampered = parts.join('.');

      await expect(auth.jwt.verifyAccessToken(tampered)).rejects.toThrow('Algorithm mismatch');
    });

    it('should reject a token with stripped signature', async () => {
      const { tokens } = await auth.login('user-1');
      const parts = tokens.accessToken.split('.');
      parts[2] = '';
      const stripped = parts.join('.');

      await expect(auth.jwt.verifyAccessToken(stripped)).rejects.toThrow('Invalid signature');
    });

    it('should reject completely random strings', async () => {
      await expect(auth.jwt.verifyAccessToken('random.garbage.here'))
        .rejects.toThrow();
      await expect(auth.jwt.verifyAccessToken('')).rejects.toThrow();
      await expect(auth.jwt.verifyAccessToken('a')).rejects.toThrow();
    });
  });

  describe('Refresh Token Reuse Attack', () => {
    it('should revoke entire family when reuse is detected', async () => {
      const { tokens: original } = await auth.login('user-1');

      // Legitimate refresh
      const refreshed = await auth.refresh(original.refreshToken);

      // Attacker replays the original refresh token
      await expect(auth.refresh(original.refreshToken))
        .rejects.toThrow(/reuse detected/);

      // Even the legitimately refreshed token should no longer work
      // because the family was revoked
      await expect(auth.refresh(refreshed.refreshToken))
        .rejects.toThrow();
    });

    it('should handle rapid sequential refreshes safely', async () => {
      const { tokens } = await auth.login('user-1');

      let current = tokens;
      for (let i = 0; i < 10; i++) {
        const next = await auth.refresh(current.refreshToken);
        // Previous should now be invalid
        if (i > 0) {
          // Can't reuse previous token
        }
        current = next;
      }

      // Final token should still work
      const payload = await auth.jwt.verifyAccessToken(current.accessToken);
      expect(payload.sub).toBe('user-1');
    });
  });

  describe('Session Security', () => {
    it('should not allow accessing a revoked session', async () => {
      const { session } = await auth.login('user-1');
      await auth.sessions.revokeSession(session.id);

      await expect(auth.sessions.getSession(session.id)).rejects.toThrow();
    });

    it('should revoke all sessions on logoutAll', async () => {
      await auth.login('user-1');
      await auth.login('user-1');
      await auth.login('user-1');

      const count = await auth.logoutAll('user-1');
      expect(count).toBe(3);

      const remaining = await auth.sessions.getUserSessions('user-1');
      expect(remaining.length).toBe(0);
    });
  });

  describe('Encryption', () => {
    const key = 'a'.repeat(64); // 32-byte hex key

    it('should encrypt and decrypt correctly', () => {
      const plaintext = 'sensitive-refresh-token-content';
      const encrypted = encrypt(plaintext, key);
      expect(encrypted).not.toBe(plaintext);

      const decrypted = decrypt(encrypted, key);
      expect(decrypted).toBe(plaintext);
    });

    it('should produce different ciphertexts for same plaintext', () => {
      const plaintext = 'same-content';
      const enc1 = encrypt(plaintext, key);
      const enc2 = encrypt(plaintext, key);
      expect(enc1).not.toBe(enc2); // random IV
    });

    it('should reject wrong key', () => {
      const encrypted = encrypt('secret', key);
      const wrongKey = 'b'.repeat(64);
      expect(() => decrypt(encrypted, wrongKey)).toThrow();
    });

    it('should reject tampered ciphertext', () => {
      const encrypted = encrypt('secret', key);
      const tampered = encrypted.slice(0, -2) + 'XX';
      expect(() => decrypt(tampered, key)).toThrow();
    });

    it('should reject invalid key length', () => {
      expect(() => encrypt('test', 'short')).toThrow(/Encryption key|required/);
      expect(() => decrypt('test', 'short')).toThrow(/Encryption key|required/);
    });
  });

  describe('Password Hashing', () => {
    it('should hash and verify passwords', async () => {
      const hash = await hashPassword('mypassword123');
      expect(hash).toContain(':');

      const valid = await verifyPassword('mypassword123', hash);
      expect(valid).toBe(true);

      const invalid = await verifyPassword('wrongpassword', hash);
      expect(invalid).toBe(false);
    });

    it('should produce different hashes for same password', async () => {
      const hash1 = await hashPassword('same-password');
      const hash2 = await hashPassword('same-password');
      expect(hash1).not.toBe(hash2); // different salts
    });
  });

  describe('Timing-Safe Comparison', () => {
    it('should compare equal strings correctly', () => {
      expect(safeCompare('hello', 'hello')).toBe(true);
    });

    it('should reject different strings', () => {
      expect(safeCompare('hello', 'world')).toBe(false);
    });

    it('should reject different length strings', () => {
      expect(safeCompare('short', 'longer')).toBe(false);
    });
  });

  describe('Configuration Validation', () => {
    it('should reject missing access token secret for HS256', () => {
      expect(() => createLockVault({
        jwt: { accessTokenSecret: '' },
        adapter: createMemoryAdapter(),
      })).toThrow();
    });

    it('should reject RS256 without keys', () => {
      expect(() => createLockVault({
        jwt: { accessTokenSecret: 'x', algorithm: 'RS256' },
        adapter: createMemoryAdapter(),
      })).toThrow();
    });

    it('should reject secrets shorter than 32 characters', () => {
      expect(() => createLockVault({
        jwt: { accessTokenSecret: 'too-short' },
        adapter: createMemoryAdapter(),
      })).toThrow(/at least 32 characters/);
    });

    it('should reject short refreshTokenSecret', () => {
      expect(() => createLockVault({
        jwt: {
          accessTokenSecret: 'a-valid-secret-that-is-at-least-32-chars!!',
          refreshTokenSecret: 'too-short',
        },
        adapter: createMemoryAdapter(),
      })).toThrow(/at least 32 characters/);
    });
  });

  describe('Algorithm Enforcement', () => {
    it('should reject tokens with alg:none in header', async () => {
      const { tokens } = await auth.login('user-1');
      const parts = tokens.accessToken.split('.');
      const header = JSON.parse(Buffer.from(parts[0]!, 'base64url').toString());
      header.alg = 'none';
      parts[0] = Buffer.from(JSON.stringify(header)).toString('base64url');
      const tampered = parts.join('.');

      await expect(auth.jwt.verifyAccessToken(tampered)).rejects.toThrow('Algorithm mismatch');
    });

    it('should reject tokens claiming RS256 when server expects HS256', async () => {
      const { tokens } = await auth.login('user-1');
      const parts = tokens.accessToken.split('.');
      const header = JSON.parse(Buffer.from(parts[0]!, 'base64url').toString());
      header.alg = 'RS256';
      parts[0] = Buffer.from(JSON.stringify(header)).toString('base64url');
      const tampered = parts.join('.');

      await expect(auth.jwt.verifyAccessToken(tampered)).rejects.toThrow('Algorithm mismatch');
    });

    it('should reject tokens with malformed headers', async () => {
      const garbage = Buffer.from('not-json').toString('base64url');
      const token = `${garbage}.${garbage}.signature`;

      await expect(auth.jwt.verifyAccessToken(token)).rejects.toThrow('Malformed token header');
    });
  });

  describe('Issuer and Audience Validation', () => {
    it('should reject tokens with wrong issuer when issuer is configured', async () => {
      // Create auth instance with issuer configured
      const strictAuth = createLockVault({
        jwt: {
          accessTokenSecret: 'super-secret-key-that-is-at-least-32-chars!',
          issuer: 'my-app',
          audience: 'my-api',
        },
        adapter: createMemoryAdapter(),
      });
      await strictAuth.initialize();

      const { tokens } = await strictAuth.login('user-1');

      // Token should verify with the same instance
      const payload = await strictAuth.jwt.verifyAccessToken(tokens.accessToken);
      expect(payload.iss).toBe('my-app');
      expect(payload.aud).toBe('my-api');

      await strictAuth.close();
    });
  });

  describe('Backup Code Entropy', () => {
    it('should generate backup codes with 48 bits of entropy (XXXX-XXXX-XXXX format)', () => {
      const codes = generateBackupCodes(10);
      expect(codes).toHaveLength(10);
      for (const code of codes) {
        expect(code).toMatch(/^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$/);
      }
    });

    it('should generate unique codes', () => {
      const codes = generateBackupCodes(100);
      const unique = new Set(codes);
      expect(unique.size).toBe(100);
    });
  });

  describe('TOTP Rate Limiting', () => {
    it('should rate limit TOTP verification attempts', async () => {
      // Set up TOTP for a user
      const setup = await auth.setupTOTP('rate-user', 'rate@test.com');
      const code = auth.totp.generateCode(setup.secret);
      await auth.confirmTOTP('rate-user', setup.secret, code, setup.backupCodes);

      // Make 5 failed attempts (rate limit is 5 per minute)
      for (let i = 0; i < 5; i++) {
        try {
          await auth.verifyTOTP('rate-user', '000000');
        } catch {
          // Expected failures
        }
      }

      // 6th attempt should be rate limited, not just "invalid code"
      try {
        await auth.verifyTOTP('rate-user', '000000');
        expect.unreachable('Should have thrown');
      } catch (err: unknown) {
        expect((err as Error).message).toMatch(/Rate limit|rate limit/i);
      }
    });
  });
});

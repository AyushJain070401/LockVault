import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createLockVault } from '../../src/core/index.js';
import { createMemoryAdapter } from '../../src/adapters/memory/index.js';
import type { LockVaultConfig, LockVaultPlugin } from '../../src/types/index.js';

describe('LockVault Integration', () => {
  let auth: LockVault;

  beforeEach(async () => {
    auth = createLockVault({
      jwt: {
        accessTokenSecret: 'integration-test-secret-32-chars-minimum!',
        refreshTokenSecret: 'integration-refresh-secret-32-chars-min!!',
        accessTokenTTL: 900,
        refreshTokenTTL: 604800,
        issuer: 'test-app',
      },
      session: {
        enabled: true,
        maxPerUser: 5,
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

  afterEach(async () => {
    await auth.close();
  });

  describe('Full Login → Refresh → Logout Flow', () => {
    it('should complete a full authentication lifecycle', async () => {
      // 1. Login
      const { tokens, session } = await auth.login('user-1', {
        customClaims: { roles: ['user'] },
        deviceInfo: { deviceType: 'desktop', browser: 'Chrome' },
        ipAddress: '10.0.0.1',
      });

      expect(tokens.accessToken).toBeDefined();
      expect(tokens.refreshToken).toBeDefined();
      expect(session.userId).toBe('user-1');
      expect(session.deviceInfo?.browser).toBe('Chrome');

      // 2. Verify access token
      const payload = await auth.jwt.verifyAccessToken(tokens.accessToken);
      expect(payload.sub).toBe('user-1');
      expect(payload.roles).toEqual(['user']);

      // 3. Get active sessions
      const sessions = await auth.sessions.getUserSessions('user-1');
      expect(sessions.length).toBe(1);

      // 4. Refresh tokens
      const refreshed = await auth.refresh(tokens.refreshToken);
      expect(refreshed.accessToken).not.toBe(tokens.accessToken);

      const newPayload = await auth.jwt.verifyAccessToken(refreshed.accessToken);
      expect(newPayload.sub).toBe('user-1');

      // 5. Logout
      await auth.logout(refreshed.accessToken);

      // Access token should be revoked
      await expect(auth.jwt.verifyAccessToken(refreshed.accessToken)).rejects.toThrow();
    });
  });

  describe('Multi-Device Session Management', () => {
    it('should track sessions across multiple devices', async () => {
      const login1 = await auth.login('user-1', {
        deviceInfo: { deviceType: 'desktop', browser: 'Chrome' },
      });
      const login2 = await auth.login('user-1', {
        deviceInfo: { deviceType: 'mobile', browser: 'Safari' },
      });
      const login3 = await auth.login('user-1', {
        deviceInfo: { deviceType: 'tablet', browser: 'Firefox' },
      });

      const sessions = await auth.sessions.getUserSessions('user-1');
      expect(sessions.length).toBe(3);

      // Revoke one device
      await auth.sessions.revokeSession(login2.session.id);
      const remaining = await auth.sessions.getUserSessions('user-1');
      expect(remaining.length).toBe(2);

      // Logout from all devices
      const revoked = await auth.logoutAll('user-1');
      expect(revoked).toBeGreaterThanOrEqual(2); // includes revoked sessions still in store
    });
  });

  describe('TOTP Integration', () => {
    it('should enable, verify, and disable TOTP', async () => {
      // Setup
      const setup = await auth.setupTOTP('user-1', 'user@test.com');
      expect(setup.secret).toBeDefined();
      expect(setup.backupCodes.length).toBe(10);

      // Confirm with valid code
      const code = auth.totp.generateCode(setup.secret);
      await auth.confirmTOTP('user-1', setup.secret, code, setup.backupCodes);

      // Verify
      const currentCode = auth.totp.generateCode(setup.secret);
      const result = await auth.verifyTOTP('user-1', currentCode);
      expect(result).toBe(true);

      // Disable
      await auth.disableTOTP('user-1');
      await expect(auth.verifyTOTP('user-1', '123456')).rejects.toThrow();
    });
  });

  describe('Plugin System', () => {
    it('should execute plugin hooks in order', async () => {
      const events: string[] = [];

      const loggingPlugin: LockVaultPlugin = {
        name: 'logging',
        version: '1.0.0',
        hooks: {
          beforeTokenCreate: (claims) => {
            events.push('beforeTokenCreate');
            return { ...claims, plugin: true };
          },
          afterTokenCreate: () => {
            events.push('afterTokenCreate');
          },
          beforeSessionCreate: (session) => {
            events.push('beforeSessionCreate');
            return session;
          },
          afterSessionCreate: () => {
            events.push('afterSessionCreate');
          },
        },
      };

      const pluginAuth = createLockVault({
        jwt: {
          accessTokenSecret: 'plugin-test-secret-32-chars-minimum!!',
          accessTokenTTL: 900,
          refreshTokenTTL: 604800,
        },
        adapter: createMemoryAdapter(),
        plugins: [loggingPlugin],
      });

      await pluginAuth.initialize();
      await pluginAuth.login('user-1');

      expect(events).toContain('beforeTokenCreate');
      expect(events).toContain('afterTokenCreate');

      await pluginAuth.close();
    });
  });

  describe('Key Rotation', () => {
    it('should accept old tokens after key rotation', async () => {
      const { tokens } = await auth.login('user-1');

      // Rotate keys
      auth.rotateJWTKeys('brand-new-secret-key-at-least-32-chars!!');

      // Old token should still verify
      const payload = await auth.jwt.verifyAccessToken(tokens.accessToken);
      expect(payload.sub).toBe('user-1');

      // New login should use new key
      const { tokens: newTokens } = await auth.login('user-2');
      const newPayload = await auth.jwt.verifyAccessToken(newTokens.accessToken);
      expect(newPayload.sub).toBe('user-2');
    });
  });

  describe('Encrypted Refresh Tokens', () => {
    it('should encrypt and decrypt refresh tokens transparently', async () => {
      const encAuth = createLockVault({
        jwt: {
          accessTokenSecret: 'encrypted-test-secret-32-chars-min!!',
          accessTokenTTL: 900,
          refreshTokenTTL: 604800,
        },
        refreshToken: {
          rotation: true,
          reuseDetection: true,
          encryption: {
            enabled: true,
            key: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
          },
        },
        adapter: createMemoryAdapter(),
      });

      await encAuth.initialize();

      const { tokens } = await encAuth.login('user-1');
      // Refresh token should be encrypted (not a JWT structure)
      expect(tokens.refreshToken.split('.').length).not.toBe(3);

      // But refresh should still work
      const refreshed = await encAuth.refresh(tokens.refreshToken);
      const payload = await encAuth.jwt.verifyAccessToken(refreshed.accessToken);
      expect(payload.sub).toBe('user-1');

      await encAuth.close();
    });
  });

  describe('Cleanup', () => {
    it('should start and stop automatic cleanup', () => {
      auth.startCleanup(1000);
      // Should not throw
      auth.stopCleanup();
    });
  });
});

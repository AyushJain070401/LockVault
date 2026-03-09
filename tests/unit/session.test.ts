import { describe, it, expect, beforeEach } from 'vitest';
import { createSessionManager } from '../../src/session/index.js';
import { createMemoryAdapter } from '../../src/adapters/memory/index.js';
import { SessionError } from '../../src/utils/errors.js';
import type { LockVaultConfig } from '../../src/types/index.js';

function createConfig(overrides?: Partial<LockVaultConfig['session']>): LockVaultConfig {
  return {
    jwt: {
      accessTokenSecret: 'test-secret-at-least-32-characters-long!',
      accessTokenTTL: 900,
      refreshTokenTTL: 604800,
    },
    session: {
      enabled: true,
      maxPerUser: 5,
      inactivityTimeout: 3600,
      ...overrides,
    },
    adapter: createMemoryAdapter(),
  };
}

describe('SessionManager', () => {
  let manager: SessionManager;
  let config: LockVaultConfig;

  beforeEach(() => {
    config = createConfig();
    manager = createSessionManager(config);
  });

  describe('createSession', () => {
    it('should create a session with all fields', async () => {
      const session = await manager.createSession('user-1', 'family-1', {
        deviceInfo: { userAgent: 'Mozilla/5.0', deviceType: 'desktop' },
        ipAddress: '192.168.1.1',
        metadata: { source: 'web' },
      });

      expect(session.id).toBeDefined();
      expect(session.userId).toBe('user-1');
      expect(session.deviceInfo?.deviceType).toBe('desktop');
      expect(session.ipAddress).toBe('192.168.1.1');
      expect(session.isRevoked).toBe(false);
      expect(session.createdAt).toBeInstanceOf(Date);
      expect(session.expiresAt).toBeInstanceOf(Date);
    });

    it('should enforce max sessions per user', async () => {
      const limitConfig = createConfig({ maxPerUser: 2 });
      const limitManager = createSessionManager(limitConfig);

      const s1 = await limitManager.createSession('user-1', 'f1');
      const s2 = await limitManager.createSession('user-1', 'f2');
      const s3 = await limitManager.createSession('user-1', 'f3');

      // Should have evicted oldest
      const sessions = await limitManager.getUserSessions('user-1');
      expect(sessions.length).toBeLessThanOrEqual(2);
    });
  });

  describe('getSession', () => {
    it('should retrieve an active session', async () => {
      const created = await manager.createSession('user-1', 'family-1');
      const fetched = await manager.getSession(created.id);

      expect(fetched.id).toBe(created.id);
      expect(fetched.userId).toBe('user-1');
    });

    it('should throw on non-existent session', async () => {
      await expect(manager.getSession('nonexistent'))
        .rejects.toThrow(/Session/);
    });

    it('should throw on revoked session', async () => {
      const session = await manager.createSession('user-1', 'f1');
      await manager.revokeSession(session.id);

      await expect(manager.getSession(session.id))
        .rejects.toThrow(/Session/);
    });
  });

  describe('getUserSessions', () => {
    it('should return all active sessions for a user', async () => {
      await manager.createSession('user-1', 'f1');
      await manager.createSession('user-1', 'f2');
      await manager.createSession('user-2', 'f3');

      const sessions = await manager.getUserSessions('user-1');
      expect(sessions.length).toBe(2);
      expect(sessions.every(s => s.userId === 'user-1')).toBe(true);
    });
  });

  describe('revokeSession', () => {
    it('should revoke a session', async () => {
      const session = await manager.createSession('user-1', 'f1');
      const result = await manager.revokeSession(session.id);

      expect(result).toBe(true);
      await expect(manager.getSession(session.id)).rejects.toThrow();
    });
  });

  describe('revokeAllSessions', () => {
    it('should revoke all sessions for a user', async () => {
      await manager.createSession('user-1', 'f1');
      await manager.createSession('user-1', 'f2');
      await manager.createSession('user-1', 'f3');

      const count = await manager.revokeAllSessions('user-1');
      expect(count).toBe(3);

      const remaining = await manager.getUserSessions('user-1');
      expect(remaining.length).toBe(0);
    });
  });

  describe('touchSession', () => {
    it('should update lastActiveAt', async () => {
      const session = await manager.createSession('user-1', 'f1');
      const originalLastActive = session.lastActiveAt;

      // Small delay to ensure time difference
      await new Promise(resolve => setTimeout(resolve, 10));

      const updated = await manager.touchSession(session.id);
      expect(updated!.lastActiveAt.getTime()).toBeGreaterThanOrEqual(originalLastActive.getTime());
    });
  });

  describe('cleanup', () => {
    it('should remove expired sessions', async () => {
      const adapter = config.adapter as createMemoryAdapter;
      // Create a session that's already expired
      await adapter.createSession({
        id: 'expired-1',
        userId: 'user-1',
        refreshTokenFamily: 'f1',
        createdAt: new Date(Date.now() - 100000),
        expiresAt: new Date(Date.now() - 50000),
        lastActiveAt: new Date(Date.now() - 100000),
        isRevoked: false,
      });

      const count = await manager.cleanup();
      expect(count).toBeGreaterThanOrEqual(1);
    });
  });
});

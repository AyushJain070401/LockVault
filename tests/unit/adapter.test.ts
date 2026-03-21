import { describe, it, expect, beforeEach } from 'vitest';
import { createMemoryAdapter } from '../../src/adapters/memory/index.js';
import type { DatabaseAdapter, Session } from '../../src/types/index.js';

describe('createMemoryAdapter', () => {
  let adapter: DatabaseAdapter;

  beforeEach(() => {
    adapter = createMemoryAdapter();
  });

  const makeSession = (overrides: Partial<Session> = {}): Session => ({
    id: 'sess-1',
    userId: 'user-1',
    refreshTokenFamily: 'family-1',
    createdAt: new Date(),
    expiresAt: new Date(Date.now() + 86400000),
    lastActiveAt: new Date(),
    isRevoked: false,
    ...overrides,
  });

  describe('Session CRUD', () => {
    it('should create and retrieve a session', async () => {
      const session = makeSession();
      await adapter.createSession(session);
      const fetched = await adapter.getSession('sess-1');
      expect(fetched!.userId).toBe('user-1');
    });

    it('should return null for non-existent session', async () => {
      const result = await adapter.getSession('nope');
      expect(result).toBeNull();
    });

    it('should update a session', async () => {
      await adapter.createSession(makeSession());
      const updated = await adapter.updateSession('sess-1', { isRevoked: true });
      expect(updated!.isRevoked).toBe(true);
    });

    it('should delete a session', async () => {
      await adapter.createSession(makeSession());
      const deleted = await adapter.deleteSession('sess-1');
      expect(deleted).toBe(true);
      expect(await adapter.getSession('sess-1')).toBeNull();
    });

    it('should list sessions by user', async () => {
      await adapter.createSession(makeSession({ id: 's1', userId: 'u1' }));
      await adapter.createSession(makeSession({ id: 's2', userId: 'u1' }));
      await adapter.createSession(makeSession({ id: 's3', userId: 'u2' }));

      const sessions = await adapter.getSessionsByUser('u1');
      expect(sessions.length).toBe(2);
    });

    it('should delete all sessions for a user', async () => {
      await adapter.createSession(makeSession({ id: 's1', userId: 'u1' }));
      await adapter.createSession(makeSession({ id: 's2', userId: 'u1' }));
      const count = await adapter.deleteSessionsByUser('u1');
      expect(count).toBe(2);
    });
  });

  describe('Refresh Token Families', () => {
    it('should store and retrieve a family', async () => {
      await adapter.storeRefreshTokenFamily('fam-1', 'user-1', 0);
      const family = await adapter.getRefreshTokenFamily('fam-1');
      expect(family!.userId).toBe('user-1');
      expect(family!.generation).toBe(0);
      expect(family!.revoked).toBe(false);
    });

    it('should increment generation', async () => {
      await adapter.storeRefreshTokenFamily('fam-1', 'user-1', 0);
      const gen = await adapter.incrementRefreshTokenGeneration('fam-1');
      expect(gen).toBe(1);
    });

    it('should revoke a family', async () => {
      await adapter.storeRefreshTokenFamily('fam-1', 'user-1', 0);
      await adapter.revokeRefreshTokenFamily('fam-1');
      const family = await adapter.getRefreshTokenFamily('fam-1');
      expect(family!.revoked).toBe(true);
    });
  });

  describe('Revocation List', () => {
    it('should add and check revocation', async () => {
      await adapter.addToRevocationList('jti-1', new Date(Date.now() + 60000));
      expect(await adapter.isRevoked('jti-1')).toBe(true);
      expect(await adapter.isRevoked('jti-2')).toBe(false);
    });

    it('should cleanup expired entries', async () => {
      await adapter.addToRevocationList('jti-old', new Date(Date.now() - 1000));
      await adapter.addToRevocationList('jti-new', new Date(Date.now() + 60000));

      const count = await adapter.cleanupRevocationList();
      expect(count).toBe(1);
      expect(await adapter.isRevoked('jti-old')).toBe(false);
      expect(await adapter.isRevoked('jti-new')).toBe(true);
    });
  });

  describe('TOTP', () => {
    it('should store and retrieve TOTP secrets', async () => {
      await adapter.storeTOTPSecret('user-1', 'SECRETKEY');
      expect(await adapter.getTOTPSecret('user-1')).toBe('SECRETKEY');
    });

    it('should manage backup codes', async () => {
      await adapter.storeBackupCodes('user-1', ['CODE1', 'CODE2', 'CODE3']);
      expect(await adapter.getBackupCodes('user-1')).toHaveLength(3);

      const consumed = await adapter.consumeBackupCode('user-1', 'CODE2');
      expect(consumed).toBe(true);
      expect(await adapter.getBackupCodes('user-1')).toHaveLength(2);
    });
  });

  describe('OAuth Links', () => {
    it('should link and retrieve OAuth accounts', async () => {
      await adapter.linkOAuthAccount('user-1', {
        provider: 'github',
        providerUserId: 'gh-123',
        linkedAt: new Date(),
      });

      const links = await adapter.getOAuthLinks('user-1');
      expect(links.length).toBe(1);
      expect(links[0]!.provider).toBe('github');
    });

    it('should find user by OAuth identity', async () => {
      await adapter.linkOAuthAccount('user-1', {
        provider: 'google',
        providerUserId: 'goog-456',
        linkedAt: new Date(),
      });

      const userId = await adapter.findUserByOAuth('google', 'goog-456');
      expect(userId).toBe('user-1');
    });

    it('should unlink OAuth accounts', async () => {
      await adapter.linkOAuthAccount('user-1', {
        provider: 'github',
        providerUserId: 'gh-123',
        linkedAt: new Date(),
      });

      const result = await adapter.unlinkOAuthAccount('user-1', 'github');
      expect(result).toBe(true);
      expect(await adapter.getOAuthLinks('user-1')).toHaveLength(0);
    });
  });
});

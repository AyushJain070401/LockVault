import { Session, DeviceInfo, LockVaultConfig, DatabaseAdapter, LockVaultHooks, AuthErrorCode } from '../types/index.js';
import { generateUUID } from '../utils/crypto.js';
import { SessionError } from '../utils/errors.js';

export interface SessionManager {
  createSession(userId: string, refreshTokenFamily: string, options?: { deviceInfo?: DeviceInfo; ipAddress?: string; metadata?: Record<string, unknown>; expiresInSeconds?: number }): Promise<Session>;
  getSession(sessionId: string): Promise<Session>;
  touchSession(sessionId: string): Promise<Session | null>;
  getUserSessions(userId: string): Promise<Session[]>;
  revokeSession(sessionId: string): Promise<boolean>;
  revokeAllSessions(userId: string): Promise<number>;
  cleanup(): Promise<number>;
}

export function createSessionManager(config: LockVaultConfig, hooks: Partial<LockVaultHooks> = {}): SessionManager {
  const adapter = config.adapter;

  return {
    async createSession(userId, refreshTokenFamily, options = {}) {
      const sessionConfig = config.session;
      if (sessionConfig?.maxPerUser) {
        const existing = await adapter.getSessionsByUser(userId);
        const active = existing.filter(s => !s.isRevoked && s.expiresAt > new Date());
        if (active.length >= sessionConfig.maxPerUser) {
          const oldest = active.sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime())[0];
          if (oldest) await adapter.deleteSession(oldest.id);
        }
      }
      const ttl = options.expiresInSeconds ?? config.jwt.refreshTokenTTL ?? 604800;
      const now = new Date();
      let sessionData: Partial<Session> = {
        id: generateUUID(), userId, refreshTokenFamily,
        deviceInfo: options.deviceInfo, ipAddress: options.ipAddress,
        createdAt: now, expiresAt: new Date(now.getTime() + ttl * 1000),
        lastActiveAt: now, isRevoked: false, metadata: options.metadata,
      };
      if (hooks.beforeSessionCreate) sessionData = await hooks.beforeSessionCreate(sessionData);
      const session = await adapter.createSession(sessionData as Session);
      if (hooks.afterSessionCreate) await hooks.afterSessionCreate(session);
      return session;
    },

    async getSession(sessionId) {
      const session = await adapter.getSession(sessionId);
      if (!session) throw new SessionError('Session not found', AuthErrorCode.SESSION_NOT_FOUND);
      if (session.isRevoked) throw new SessionError('Session has been revoked', AuthErrorCode.SESSION_REVOKED);
      if (session.expiresAt < new Date()) throw new SessionError('Session has expired', AuthErrorCode.SESSION_EXPIRED);
      const inactivityTimeout = config.session?.inactivityTimeout;
      if (inactivityTimeout) {
        const inactiveMs = Date.now() - session.lastActiveAt.getTime();
        if (inactiveMs > inactivityTimeout * 1000) {
          await adapter.updateSession(sessionId, { isRevoked: true });
          throw new SessionError('Session expired due to inactivity', AuthErrorCode.SESSION_EXPIRED);
        }
      }
      return session;
    },

    async touchSession(sessionId) { return adapter.updateSession(sessionId, { lastActiveAt: new Date() }); },
    async getUserSessions(userId) {
      const sessions = await adapter.getSessionsByUser(userId);
      return sessions.filter(s => !s.isRevoked && s.expiresAt > new Date());
    },
    async revokeSession(sessionId) { const u = await adapter.updateSession(sessionId, { isRevoked: true }); return u !== null; },
    async revokeAllSessions(userId) { return adapter.deleteSessionsByUser(userId); },
    async cleanup() { return adapter.deleteExpiredSessions(); },
  };
}

import {
  Session,
  DeviceInfo,
  LockVaultConfig,
  DatabaseAdapter,
  LockVaultHooks,
  AuthErrorCode,
} from '../types/index.js';
import { generateUUID } from '../utils/crypto.js';
import { SessionError } from '../utils/errors.js';

export class SessionManager {
  private readonly config: LockVaultConfig;
  private readonly adapter: DatabaseAdapter;
  private readonly hooks: Partial<LockVaultHooks>;

  constructor(config: LockVaultConfig, hooks: Partial<LockVaultHooks> = {}) {
    this.config = config;
    this.adapter = config.adapter;
    this.hooks = hooks;
  }

  /**
   * Create a new session for a user
   */
  async createSession(
    userId: string,
    refreshTokenFamily: string,
    options: {
      deviceInfo?: DeviceInfo;
      ipAddress?: string;
      metadata?: Record<string, unknown>;
      expiresInSeconds?: number;
    } = {},
  ): Promise<Session> {
    const sessionConfig = this.config.session;

    // Enforce max sessions per user
    if (sessionConfig?.maxPerUser) {
      const existing = await this.adapter.getSessionsByUser(userId);
      const activeSessions = existing.filter(s => !s.isRevoked && s.expiresAt > new Date());

      if (activeSessions.length >= sessionConfig.maxPerUser) {
        // Revoke oldest session to make room
        const oldest = activeSessions.sort(
          (a, b) => a.createdAt.getTime() - b.createdAt.getTime(),
        )[0];
        if (oldest) {
          await this.adapter.deleteSession(oldest.id);
        }
      }
    }

    const ttl = options.expiresInSeconds ?? this.config.jwt.refreshTokenTTL ?? 604800;
    const now = new Date();

    let sessionData: Partial<Session> = {
      id: generateUUID(),
      userId,
      refreshTokenFamily,
      deviceInfo: options.deviceInfo,
      ipAddress: options.ipAddress,
      createdAt: now,
      expiresAt: new Date(now.getTime() + ttl * 1000),
      lastActiveAt: now,
      isRevoked: false,
      metadata: options.metadata,
    };

    if (this.hooks.beforeSessionCreate) {
      sessionData = await this.hooks.beforeSessionCreate(sessionData);
    }

    const session = await this.adapter.createSession(sessionData as Session);

    if (this.hooks.afterSessionCreate) {
      await this.hooks.afterSessionCreate(session);
    }

    return session;
  }

  /**
   * Get a session by ID
   */
  async getSession(sessionId: string): Promise<Session> {
    const session = await this.adapter.getSession(sessionId);

    if (!session) {
      throw new SessionError('Session not found', AuthErrorCode.SESSION_NOT_FOUND);
    }

    if (session.isRevoked) {
      throw new SessionError('Session has been revoked', AuthErrorCode.SESSION_REVOKED);
    }

    if (session.expiresAt < new Date()) {
      throw new SessionError('Session has expired', AuthErrorCode.SESSION_EXPIRED);
    }

    // Check inactivity timeout
    const inactivityTimeout = this.config.session?.inactivityTimeout;
    if (inactivityTimeout) {
      const inactiveMs = Date.now() - session.lastActiveAt.getTime();
      if (inactiveMs > inactivityTimeout * 1000) {
        await this.revokeSession(sessionId);
        throw new SessionError('Session expired due to inactivity', AuthErrorCode.SESSION_EXPIRED);
      }
    }

    return session;
  }

  /**
   * Touch/renew a session (update lastActiveAt)
   */
  async touchSession(sessionId: string): Promise<Session | null> {
    return this.adapter.updateSession(sessionId, { lastActiveAt: new Date() });
  }

  /**
   * Get all active sessions for a user
   */
  async getUserSessions(userId: string): Promise<Session[]> {
    const sessions = await this.adapter.getSessionsByUser(userId);
    return sessions.filter(s => !s.isRevoked && s.expiresAt > new Date());
  }

  /**
   * Revoke a specific session
   */
  async revokeSession(sessionId: string): Promise<boolean> {
    const updated = await this.adapter.updateSession(sessionId, { isRevoked: true });
    return updated !== null;
  }

  /**
   * Revoke all sessions for a user
   */
  async revokeAllSessions(userId: string): Promise<number> {
    return this.adapter.deleteSessionsByUser(userId);
  }

  /**
   * Clean up expired sessions
   */
  async cleanup(): Promise<number> {
    return this.adapter.deleteExpiredSessions();
  }
}

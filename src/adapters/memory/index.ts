import { DatabaseAdapter, Session, OAuthLink } from '../../types/index.js';

/**
 * In-memory adapter for testing and development.
 * Also serves as the reference implementation for custom adapters.
 */
export class MemoryAdapter implements DatabaseAdapter {
  private sessions = new Map<string, Session>();
  private refreshFamilies = new Map<string, { userId: string; generation: number; revoked: boolean }>();
  private revocationList = new Map<string, Date>();
  private totpSecrets = new Map<string, string>();
  private backupCodes = new Map<string, string[]>();
  private oauthLinks = new Map<string, OAuthLink[]>(); // userId -> links

  // ─── Sessions ───────────────────────────────────────────────────────────

  async createSession(session: Session): Promise<Session> {
    this.sessions.set(session.id, { ...session });
    return { ...session };
  }

  async getSession(sessionId: string): Promise<Session | null> {
    const s = this.sessions.get(sessionId);
    return s ? { ...s } : null;
  }

  async getSessionsByUser(userId: string): Promise<Session[]> {
    return [...this.sessions.values()].filter(s => s.userId === userId).map(s => ({ ...s }));
  }

  async updateSession(sessionId: string, updates: Partial<Session>): Promise<Session | null> {
    const s = this.sessions.get(sessionId);
    if (!s) return null;
    const updated = { ...s, ...updates };
    this.sessions.set(sessionId, updated);
    return { ...updated };
  }

  async deleteSession(sessionId: string): Promise<boolean> {
    return this.sessions.delete(sessionId);
  }

  async deleteSessionsByUser(userId: string): Promise<number> {
    let count = 0;
    for (const [id, s] of this.sessions) {
      if (s.userId === userId) {
        this.sessions.delete(id);
        count++;
      }
    }
    return count;
  }

  async deleteExpiredSessions(): Promise<number> {
    const now = new Date();
    let count = 0;
    for (const [id, s] of this.sessions) {
      if (s.expiresAt < now || s.isRevoked) {
        this.sessions.delete(id);
        count++;
      }
    }
    return count;
  }

  // ─── Refresh Token Families ─────────────────────────────────────────────

  async storeRefreshTokenFamily(family: string, userId: string, generation: number): Promise<void> {
    this.refreshFamilies.set(family, { userId, generation, revoked: false });
  }

  async getRefreshTokenFamily(family: string): Promise<{ userId: string; generation: number; revoked: boolean } | null> {
    return this.refreshFamilies.get(family) ?? null;
  }

  async revokeRefreshTokenFamily(family: string): Promise<void> {
    const record = this.refreshFamilies.get(family);
    if (record) {
      record.revoked = true;
    }
  }

  async incrementRefreshTokenGeneration(family: string): Promise<number> {
    const record = this.refreshFamilies.get(family);
    if (!record) throw new Error(`Family ${family} not found`);
    record.generation++;
    return record.generation;
  }

  // ─── Revocation List ────────────────────────────────────────────────────

  async addToRevocationList(jti: string, expiresAt: Date): Promise<void> {
    this.revocationList.set(jti, expiresAt);
  }

  async isRevoked(jti: string): Promise<boolean> {
    return this.revocationList.has(jti);
  }

  async cleanupRevocationList(): Promise<number> {
    const now = new Date();
    let count = 0;
    for (const [jti, exp] of this.revocationList) {
      if (exp < now) {
        this.revocationList.delete(jti);
        count++;
      }
    }
    return count;
  }

  // ─── TOTP ──────────────────────────────────────────────────────────────

  async storeTOTPSecret(userId: string, secret: string): Promise<void> {
    this.totpSecrets.set(userId, secret);
  }

  async getTOTPSecret(userId: string): Promise<string | null> {
    return this.totpSecrets.get(userId) ?? null;
  }

  async removeTOTPSecret(userId: string): Promise<void> {
    this.totpSecrets.delete(userId);
    this.backupCodes.delete(userId);
  }

  async storeBackupCodes(userId: string, codes: string[]): Promise<void> {
    this.backupCodes.set(userId, [...codes]);
  }

  async getBackupCodes(userId: string): Promise<string[]> {
    return this.backupCodes.get(userId) ?? [];
  }

  async consumeBackupCode(userId: string, code: string): Promise<boolean> {
    const codes = this.backupCodes.get(userId);
    if (!codes) return false;
    const normalized = code.toUpperCase();
    const idx = codes.findIndex(c => c === normalized);
    if (idx === -1) return false;
    codes.splice(idx, 1);
    return true;
  }

  // ─── OAuth ─────────────────────────────────────────────────────────────

  async linkOAuthAccount(userId: string, link: OAuthLink): Promise<void> {
    const links = this.oauthLinks.get(userId) ?? [];
    const existing = links.findIndex(l => l.provider === link.provider);
    if (existing >= 0) {
      links[existing] = link;
    } else {
      links.push(link);
    }
    this.oauthLinks.set(userId, links);
  }

  async getOAuthLinks(userId: string): Promise<OAuthLink[]> {
    return this.oauthLinks.get(userId) ?? [];
  }

  async findUserByOAuth(provider: string, providerUserId: string): Promise<string | null> {
    for (const [userId, links] of this.oauthLinks) {
      if (links.some(l => l.provider === provider && l.providerUserId === providerUserId)) {
        return userId;
      }
    }
    return null;
  }

  async unlinkOAuthAccount(userId: string, provider: string): Promise<boolean> {
    const links = this.oauthLinks.get(userId);
    if (!links) return false;
    const filtered = links.filter(l => l.provider !== provider);
    if (filtered.length === links.length) return false;
    this.oauthLinks.set(userId, filtered);
    return true;
  }

  // ─── Lifecycle ─────────────────────────────────────────────────────────

  async initialize(): Promise<void> { /* no-op */ }

  async close(): Promise<void> {
    this.sessions.clear();
    this.refreshFamilies.clear();
    this.revocationList.clear();
    this.totpSecrets.clear();
    this.backupCodes.clear();
    this.oauthLinks.clear();
  }
}

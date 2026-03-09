import { DatabaseAdapter, Session, OAuthLink } from '../../types/index.js';

export function createMemoryAdapter(): DatabaseAdapter {
  const sessions = new Map<string, Session>();
  const refreshFamilies = new Map<string, { userId: string; generation: number; revoked: boolean }>();
  const revocationList = new Map<string, Date>();
  const totpSecrets = new Map<string, string>();
  const backupCodes = new Map<string, string[]>();
  const oauthLinks = new Map<string, OAuthLink[]>();

  return {
    async createSession(session) { sessions.set(session.id, { ...session }); return { ...session }; },
    async getSession(sessionId) { const s = sessions.get(sessionId); return s ? { ...s } : null; },
    async getSessionsByUser(userId) { return [...sessions.values()].filter(s => s.userId === userId).map(s => ({ ...s })); },
    async updateSession(sessionId, updates) { const s = sessions.get(sessionId); if (!s) return null; const updated = { ...s, ...updates }; sessions.set(sessionId, updated); return { ...updated }; },
    async deleteSession(sessionId) { return sessions.delete(sessionId); },
    async deleteSessionsByUser(userId) { let count = 0; for (const [id, s] of sessions) { if (s.userId === userId) { sessions.delete(id); count++; } } return count; },
    async deleteExpiredSessions() { const now = new Date(); let count = 0; for (const [id, s] of sessions) { if (s.expiresAt < now || s.isRevoked) { sessions.delete(id); count++; } } return count; },
    async storeRefreshTokenFamily(family, userId, generation) { refreshFamilies.set(family, { userId, generation, revoked: false }); },
    async getRefreshTokenFamily(family) { return refreshFamilies.get(family) ?? null; },
    async revokeRefreshTokenFamily(family) { const r = refreshFamilies.get(family); if (r) r.revoked = true; },
    async incrementRefreshTokenGeneration(family) { const r = refreshFamilies.get(family); if (!r) throw new Error(`Family ${family} not found`); r.generation++; return r.generation; },
    async addToRevocationList(jti, expiresAt) { revocationList.set(jti, expiresAt); },
    async isRevoked(jti) { return revocationList.has(jti); },
    async cleanupRevocationList() { const now = new Date(); let count = 0; for (const [jti, exp] of revocationList) { if (exp < now) { revocationList.delete(jti); count++; } } return count; },
    async storeTOTPSecret(userId, secret) { totpSecrets.set(userId, secret); },
    async getTOTPSecret(userId) { return totpSecrets.get(userId) ?? null; },
    async removeTOTPSecret(userId) { totpSecrets.delete(userId); backupCodes.delete(userId); },
    async storeBackupCodes(userId, codes) { backupCodes.set(userId, [...codes]); },
    async getBackupCodes(userId) { return backupCodes.get(userId) ?? []; },
    async consumeBackupCode(userId, code) { const codes = backupCodes.get(userId); if (!codes) return false; const n = code.toUpperCase(); const idx = codes.findIndex(c => c === n); if (idx === -1) return false; codes.splice(idx, 1); return true; },
    async linkOAuthAccount(userId, link) { const links = oauthLinks.get(userId) ?? []; const existing = links.findIndex(l => l.provider === link.provider); if (existing >= 0) links[existing] = link; else links.push(link); oauthLinks.set(userId, links); },
    async getOAuthLinks(userId) { return oauthLinks.get(userId) ?? []; },
    async findUserByOAuth(provider, providerUserId) { for (const [userId, links] of oauthLinks) { if (links.some(l => l.provider === provider && l.providerUserId === providerUserId)) return userId; } return null; },
    async unlinkOAuthAccount(userId, provider) { const links = oauthLinks.get(userId); if (!links) return false; const filtered = links.filter(l => l.provider !== provider); if (filtered.length === links.length) return false; oauthLinks.set(userId, filtered); return true; },
    async initialize() {},
    async close() { sessions.clear(); refreshFamilies.clear(); revocationList.clear(); totpSecrets.clear(); backupCodes.clear(); oauthLinks.clear(); },
  };
}

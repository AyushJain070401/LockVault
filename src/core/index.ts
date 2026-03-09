import { LockVaultConfig, TokenPair, Session, DeviceInfo, TOTPSetupResult, OAuthProviderConfig, OAuthProviderPreset, OAuthUserProfile, OAuthTokenResponse, DatabaseAdapter, LockVaultPlugin, LockVaultHooks } from '../types/index.js';
import { createJWTManager, JWTManager } from '../jwt/index.js';
import { createSessionManager, SessionManager } from '../session/index.js';
import { createTOTPManager, TOTPManager } from '../totp/index.js';
import { createOAuthManager, OAuthManager } from '../oauth/index.js';
import { ConfigurationError } from '../utils/errors.js';
import { generateId } from '../utils/crypto.js';

export interface LockVault {
  readonly jwt: JWTManager;
  readonly sessions: SessionManager;
  readonly totp: TOTPManager;
  readonly oauth: OAuthManager;
  readonly adapter: DatabaseAdapter;
  initialize(): Promise<void>;
  startCleanup(intervalMs?: number): void;
  stopCleanup(): void;
  login(userId: string, options?: { customClaims?: Record<string, unknown>; deviceInfo?: DeviceInfo; ipAddress?: string; metadata?: Record<string, unknown> }): Promise<{ tokens: TokenPair; session: Session }>;
  refresh(refreshToken: string, customClaims?: Record<string, unknown>): Promise<TokenPair>;
  logout(accessToken: string): Promise<void>;
  logoutAll(userId: string): Promise<number>;
  setupTOTP(userId: string, email?: string): Promise<TOTPSetupResult>;
  confirmTOTP(userId: string, secret: string, code: string, backupCodes: string[]): Promise<boolean>;
  verifyTOTP(userId: string, code: string): Promise<boolean>;
  disableTOTP(userId: string): Promise<void>;
  registerOAuthProvider(name: string, config: OAuthProviderConfig): void;
  registerOAuthPreset(preset: OAuthProviderPreset, config: { clientId: string; clientSecret: string; redirectUri: string }): void;
  getOAuthAuthorizationUrl(provider: string, metadata?: Record<string, unknown>): Promise<string>;
  handleOAuthCallback(provider: string, code: string, state: string): Promise<{ profile: OAuthUserProfile; tokens: OAuthTokenResponse }>;
  rotateJWTKeys(newSecret: string): void;
  close(): Promise<void>;
}

export function createLockVault(config: LockVaultConfig): LockVault {
  const ASYMMETRIC_ALGS = new Set(['RS256', 'ES256', 'ES384', 'ES512', 'EdDSA']);

  if (!config.adapter) throw new ConfigurationError('A database adapter is required');
  const alg = config.jwt?.algorithm ?? 'HS256';
  if (!config.jwt?.accessTokenSecret && !ASYMMETRIC_ALGS.has(alg)) throw new ConfigurationError('jwt.accessTokenSecret is required');

  const normalizedConfig: LockVaultConfig = {
    ...config,
    jwt: { algorithm: 'HS256', accessTokenTTL: 900, refreshTokenTTL: 604800, ...config.jwt },
    session: { enabled: true, maxPerUser: 10, ...config.session },
    refreshToken: { rotation: true, reuseDetection: true, familyRevocationOnReuse: true, ...config.refreshToken },
  };

  // Merge plugin hooks
  const hooks: Partial<LockVaultHooks> = {};
  for (const plugin of config.plugins ?? []) {
    if (plugin.hooks) {
      for (const [key, fn] of Object.entries(plugin.hooks)) {
        const hookKey = key as keyof LockVaultHooks;
        const existing = hooks[hookKey];
        if (existing) {
          hooks[hookKey] = (async (...args: unknown[]) => { await (existing as Function)(...args); return (fn as Function)(...args); }) as never;
        } else { hooks[hookKey] = fn as never; }
      }
    }
  }

  const adapter = config.adapter;
  const jwt = createJWTManager(normalizedConfig, hooks);
  const sessions = createSessionManager(normalizedConfig, hooks);
  const totp = createTOTPManager(normalizedConfig.totp ?? {}, adapter, normalizedConfig.kvStore);
  const oauth = createOAuthManager(normalizedConfig.oauth?.providers ?? {}, adapter, normalizedConfig.oauth?.stateStore);

  let cleanupInterval: ReturnType<typeof setInterval> | undefined;

  return {
    jwt, sessions, totp, oauth, adapter,

    async initialize() { if (adapter.initialize) await adapter.initialize(); },

    startCleanup(intervalMs = 3600_000) {
      this.stopCleanup();
      cleanupInterval = setInterval(async () => {
        try { await adapter.deleteExpiredSessions(); await adapter.cleanupRevocationList(); }
        catch (err) { if (hooks.onError) await hooks.onError(err as Error, 'cleanup'); }
      }, intervalMs);
      if (cleanupInterval.unref) cleanupInterval.unref();
    },

    stopCleanup() { if (cleanupInterval) { clearInterval(cleanupInterval); cleanupInterval = undefined; } },

    async login(userId, options = {}) {
      const session = await sessions.createSession(userId, generateId(16), { deviceInfo: options.deviceInfo, ipAddress: options.ipAddress, metadata: options.metadata });
      const tokens = await jwt.createTokenPair(userId, { ...options.customClaims, sid: session.id }, session.id);
      return { tokens, session };
    },

    async refresh(refreshToken, customClaims?) { return jwt.refreshTokens(refreshToken, customClaims); },

    async logout(accessToken) {
      try { const payload = await jwt.verifyAccessToken(accessToken); await jwt.revokeToken(accessToken); if (payload.sid) await sessions.revokeSession(payload.sid as string); } catch {}
    },

    async logoutAll(userId) { return sessions.revokeAllSessions(userId); },
    async setupTOTP(userId, email?) { return totp.setup(userId, email); },
    async confirmTOTP(userId, secret, code, backupCodes) { return totp.confirmSetup(userId, secret, code, backupCodes); },
    async verifyTOTP(userId, code) { return totp.verify(userId, code); },
    async disableTOTP(userId) { return totp.disable(userId); },
    registerOAuthProvider(name, cfg) { oauth.registerProvider(name, cfg); },
    registerOAuthPreset(preset, cfg) { oauth.registerPreset(preset, cfg); },
    async getOAuthAuthorizationUrl(provider, metadata?) { return oauth.getAuthorizationUrl(provider, { metadata }); },
    async handleOAuthCallback(provider, code, state) { return oauth.handleCallback(provider, code, state); },
    rotateJWTKeys(newSecret) { jwt.rotateKeys(newSecret); },

    async close() { this.stopCleanup(); oauth.destroy(); if (adapter.close) await adapter.close(); },
  };
}

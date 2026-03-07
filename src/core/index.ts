import {
  LockVaultConfig,
  TokenPair,

  Session,
  DeviceInfo,
  TOTPSetupResult,
  OAuthProviderConfig,
  OAuthProviderPreset,
  OAuthUserProfile,
  OAuthTokenResponse,
  DatabaseAdapter,
  LockVaultPlugin,
  LockVaultHooks,
} from '../types/index.js';
import { JWTManager } from '../jwt/index.js';
import { SessionManager } from '../session/index.js';
import { TOTPManager } from '../totp/index.js';
import { OAuthManager } from '../oauth/index.js';
import { ConfigurationError } from '../utils/errors.js';
import { generateId } from '../utils/crypto.js';

export class LockVault {
  public readonly jwt: JWTManager;
  public readonly sessions: SessionManager;
  public readonly totp: TOTPManager;
  public readonly oauth: OAuthManager;
  public readonly adapter: DatabaseAdapter;

  private readonly config: LockVaultConfig;
  private readonly hooks: Partial<LockVaultHooks>;
  private cleanupInterval?: ReturnType<typeof setInterval>;

  constructor(config: LockVaultConfig) {
    this.config = this.validateAndNormalize(config);
    this.adapter = config.adapter;
    this.hooks = this.mergePluginHooks(config.plugins ?? []);

    this.jwt = new JWTManager(this.config, this.hooks);
    this.sessions = new SessionManager(this.config, this.hooks);
    this.totp = new TOTPManager(this.config.totp ?? {}, this.adapter, this.config.kvStore);
    this.oauth = new OAuthManager(this.config.oauth?.providers ?? {}, this.adapter, this.config.oauth?.stateStore);
  }

  // ─── Initialization ────────────────────────────────────────────────────

  async initialize(): Promise<void> {
    if (this.adapter.initialize) {
      await this.adapter.initialize();
    }
  }

  /**
   * Start automatic cleanup of expired sessions and revocation entries.
   */
  startCleanup(intervalMs: number = 3600_000): void {
    this.stopCleanup();
    this.cleanupInterval = setInterval(async () => {
      try {
        await this.adapter.deleteExpiredSessions();
        await this.adapter.cleanupRevocationList();
      } catch (err) {
        if (this.hooks.onError) {
          await this.hooks.onError(err as Error, 'cleanup');
        }
      }
    }, intervalMs);
    // Allow process to exit even if interval is active
    if (this.cleanupInterval.unref) {
      this.cleanupInterval.unref();
    }
  }

  stopCleanup(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = undefined;
    }
  }

  // ─── High-Level Authentication API ──────────────────────────────────────

  /**
   * Authenticate a user and create a full token pair + session.
   */
  async login(
    userId: string,
    options: {
      customClaims?: Record<string, unknown>;
      deviceInfo?: DeviceInfo;
      ipAddress?: string;
      metadata?: Record<string, unknown>;
    } = {},
  ): Promise<{ tokens: TokenPair; session: Session }> {
    // Create session first so we can embed the session ID in the tokens
    const session = await this.sessions.createSession(
      userId,
      generateId(16), // family tracking id
      {
        deviceInfo: options.deviceInfo,
        ipAddress: options.ipAddress,
        metadata: options.metadata,
      },
    );

    // Create tokens with session ID embedded
    const tokens = await this.jwt.createTokenPair(
      userId,
      { ...options.customClaims, sid: session.id },
      session.id,
    );

    return { tokens, session };
  }

  /**
   * Refresh tokens with automatic rotation.
   */
  async refresh(
    refreshToken: string,
    customClaims?: Record<string, unknown>,
  ): Promise<TokenPair> {
    return this.jwt.refreshTokens(refreshToken, customClaims);
  }

  /**
   * Logout — revoke the token and session.
   */
  async logout(accessToken: string): Promise<void> {
    try {
      const payload = await this.jwt.verifyAccessToken(accessToken);
      await this.jwt.revokeToken(accessToken);

      if (payload.sid) {
        await this.sessions.revokeSession(payload.sid as string);
      }
    } catch {
      // Already expired/invalid — that's fine for logout
    }
  }

  /**
   * Logout from all devices — revoke all sessions.
   */
  async logoutAll(userId: string): Promise<number> {
    return this.sessions.revokeAllSessions(userId);
  }

  // ─── TOTP Convenience Methods ──────────────────────────────────────────

  async setupTOTP(userId: string, email?: string): Promise<TOTPSetupResult> {
    return this.totp.setup(userId, email);
  }

  async confirmTOTP(userId: string, secret: string, code: string, backupCodes: string[]): Promise<boolean> {
    return this.totp.confirmSetup(userId, secret, code, backupCodes);
  }

  async verifyTOTP(userId: string, code: string): Promise<boolean> {
    return this.totp.verify(userId, code);
  }

  async disableTOTP(userId: string): Promise<void> {
    return this.totp.disable(userId);
  }

  // ─── OAuth Convenience Methods ─────────────────────────────────────────

  registerOAuthProvider(name: string, config: OAuthProviderConfig): void {
    this.oauth.registerProvider(name, config);
  }

  registerOAuthPreset(
    preset: OAuthProviderPreset,
    config: { clientId: string; clientSecret: string; redirectUri: string },
  ): void {
    this.oauth.registerPreset(preset, config);
  }

  async getOAuthAuthorizationUrl(provider: string, metadata?: Record<string, unknown>): Promise<string> {
    return this.oauth.getAuthorizationUrl(provider, { metadata });
  }

  async handleOAuthCallback(
    provider: string,
    code: string,
    state: string,
  ): Promise<{ profile: OAuthUserProfile; tokens: OAuthTokenResponse }> {
    return this.oauth.handleCallback(provider, code, state);
  }

  // ─── Key Rotation ──────────────────────────────────────────────────────

  rotateJWTKeys(newSecret: string): void {
    this.jwt.rotateKeys(newSecret);
  }

  // ─── Shutdown ──────────────────────────────────────────────────────────

  async close(): Promise<void> {
    this.stopCleanup();
    this.oauth.destroy();
    if (this.adapter.close) {
      await this.adapter.close();
    }
  }

  // ─── Internals ─────────────────────────────────────────────────────────

  private static readonly ASYMMETRIC_ALGS = new Set(['RS256', 'ES256', 'ES384', 'ES512', 'EdDSA']);

  private validateAndNormalize(config: LockVaultConfig): LockVaultConfig {
    if (!config.adapter) {
      throw new ConfigurationError('A database adapter is required');
    }
    const alg = config.jwt?.algorithm ?? 'HS256';
    if (!config.jwt?.accessTokenSecret && !LockVault.ASYMMETRIC_ALGS.has(alg)) {
      throw new ConfigurationError('jwt.accessTokenSecret is required');
    }

    return {
      ...config,
      jwt: {
        algorithm: 'HS256',
        accessTokenTTL: 900,
        refreshTokenTTL: 604800,
        ...config.jwt,
      },
      session: {
        enabled: true,
        maxPerUser: 10,
        ...config.session,
      },
      refreshToken: {
        rotation: true,
        reuseDetection: true,
        familyRevocationOnReuse: true,
        ...config.refreshToken,
      },
    };
  }

  private mergePluginHooks(plugins: LockVaultPlugin[]): Partial<LockVaultHooks> {
    const hooks: Partial<LockVaultHooks> = {};

    for (const plugin of plugins) {
      if (plugin.hooks) {
        for (const [key, fn] of Object.entries(plugin.hooks)) {
          const hookKey = key as keyof LockVaultHooks;
          const existing = hooks[hookKey];
          if (existing) {
            // Chain hooks
            hooks[hookKey] = (async (...args: unknown[]) => {
              await (existing as Function)(...args);
              return (fn as Function)(...args);
            }) as never;
          } else {
            hooks[hookKey] = fn as never;
          }
        }
      }
    }

    return hooks;
  }
}

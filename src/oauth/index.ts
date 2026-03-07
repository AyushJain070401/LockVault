import {
  OAuthProviderConfig,
  OAuthUserProfile,
  OAuthTokenResponse,
  OAuthProviderPreset,
  DatabaseAdapter,
  OAuthLink,
  KeyValueStore,
} from '../types/index.js';
import { generateId } from '../utils/crypto.js';
import { OAuthError } from '../utils/errors.js';
import { MemoryKeyValueStore } from '../store/index.js';

// ─── Provider Presets ───────────────────────────────────────────────────────

const PROVIDER_PRESETS: Record<OAuthProviderPreset, Omit<OAuthProviderConfig, 'clientId' | 'clientSecret' | 'redirectUri'>> = {
  google: {
    authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    userInfoUrl: 'https://www.googleapis.com/oauth2/v2/userinfo',
    scopes: ['openid', 'email', 'profile'],
    mapProfile: (p) => ({
      id: String(p.id),
      email: String(p.email ?? ''),
      name: String(p.name ?? ''),
      avatar: String(p.picture ?? ''),
      raw: p,
    }),
  },
  github: {
    authorizationUrl: 'https://github.com/login/oauth/authorize',
    tokenUrl: 'https://github.com/login/oauth/access_token',
    userInfoUrl: 'https://api.github.com/user',
    scopes: ['read:user', 'user:email'],
    mapProfile: (p) => ({
      id: String(p.id),
      email: String(p.email ?? ''),
      name: String(p.name ?? p.login ?? ''),
      avatar: String(p.avatar_url ?? ''),
      raw: p,
    }),
  },
  facebook: {
    authorizationUrl: 'https://www.facebook.com/v18.0/dialog/oauth',
    tokenUrl: 'https://graph.facebook.com/v18.0/oauth/access_token',
    userInfoUrl: 'https://graph.facebook.com/me?fields=id,name,email,picture',
    scopes: ['email', 'public_profile'],
    mapProfile: (p) => ({
      id: String(p.id),
      email: String(p.email ?? ''),
      name: String(p.name ?? ''),
      avatar: (p.picture as Record<string, Record<string, string>>)?.data?.url ?? '',
      raw: p,
    }),
  },
  apple: {
    authorizationUrl: 'https://appleid.apple.com/auth/authorize',
    tokenUrl: 'https://appleid.apple.com/auth/token',
    userInfoUrl: '',
    scopes: ['name', 'email'],
    mapProfile: (p) => ({
      id: String(p.sub),
      email: String(p.email ?? ''),
      name: String(p.name ?? ''),
      raw: p,
    }),
  },
  microsoft: {
    authorizationUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
    userInfoUrl: 'https://graph.microsoft.com/v1.0/me',
    scopes: ['openid', 'email', 'profile'],
    mapProfile: (p) => ({
      id: String(p.id),
      email: String(p.mail ?? p.userPrincipalName ?? ''),
      name: String(p.displayName ?? ''),
      raw: p,
    }),
  },
};

export class OAuthManager {
  private readonly providers: Map<string, OAuthProviderConfig> = new Map();
  private readonly adapter: DatabaseAdapter;
  private readonly stateStore: KeyValueStore;
  private readonly ownsStateStore: boolean;

  constructor(
    providerConfigs: Record<string, OAuthProviderConfig> = {},
    adapter: DatabaseAdapter,
    stateStore?: KeyValueStore,
  ) {
    this.adapter = adapter;
    this.ownsStateStore = !stateStore;
    this.stateStore = stateStore ?? new MemoryKeyValueStore({ maxEntries: 10_000 });

    for (const [name, config] of Object.entries(providerConfigs)) {
      this.providers.set(name, config);
    }
  }

  /**
   * Clean up internal resources. Only destroys the state store if it was
   * created internally (not user-provided).
   */
  destroy(): void {
    if (this.ownsStateStore && 'destroy' in this.stateStore) {
      (this.stateStore as MemoryKeyValueStore).destroy();
    }
  }

  /**
   * Register a provider using a preset (Google, GitHub, etc.)
   */
  registerPreset(
    preset: OAuthProviderPreset,
    config: { clientId: string; clientSecret: string; redirectUri: string; scopes?: string[] },
  ): void {
    const base = PROVIDER_PRESETS[preset];
    this.providers.set(preset, {
      ...base,
      ...config,
      scopes: config.scopes ?? base.scopes,
    });
  }

  /**
   * Register a custom OAuth provider
   */
  registerProvider(name: string, config: OAuthProviderConfig): void {
    this.providers.set(name, config);
  }

  /**
   * Generate the authorization URL for redirect
   */
  async getAuthorizationUrl(
    providerName: string,
    options: { state?: string; metadata?: Record<string, unknown> } = {},
  ): Promise<string> {
    const provider = this.getProvider(providerName);
    const state = options.state ?? generateId(32);

    // Store state for CSRF verification (TTL: 10 minutes)
    const stateData = JSON.stringify({
      provider: providerName,
      metadata: options.metadata,
    });
    await this.stateStore.set(`oauth_state:${state}`, stateData, 600_000);

    const params = new URLSearchParams({
      client_id: provider.clientId,
      redirect_uri: provider.redirectUri,
      response_type: 'code',
      state,
      ...(provider.scopes?.length && { scope: provider.scopes.join(' ') }),
    });

    return `${provider.authorizationUrl}?${params.toString()}`;
  }

  /**
   * Handle the OAuth callback — exchange code for tokens and fetch profile
   */
  async handleCallback(
    providerName: string,
    code: string,
    state: string,
  ): Promise<{ profile: OAuthUserProfile; tokens: OAuthTokenResponse }> {
    // Verify state
    const raw = await this.stateStore.get(`oauth_state:${state}`);
    if (!raw) {
      throw new OAuthError('Invalid or expired OAuth state', { provider: providerName });
    }

    const stateData = JSON.parse(raw) as { provider: string; metadata?: Record<string, unknown> };
    if (stateData.provider !== providerName) {
      throw new OAuthError('Invalid or expired OAuth state', { provider: providerName });
    }

    // Delete state immediately (one-time use)
    await this.stateStore.delete(`oauth_state:${state}`);

    const provider = this.getProvider(providerName);

    // Exchange authorization code for tokens
    const tokens = await this.exchangeCode(provider, code);

    // Fetch user profile
    const profile = await this.fetchProfile(provider, tokens.access_token);

    return { profile, tokens };
  }

  /**
   * Link an OAuth account to an existing user
   */
  async linkAccount(
    userId: string,
    providerName: string,
    profile: OAuthUserProfile,
    tokens: OAuthTokenResponse,
  ): Promise<void> {
    const link: OAuthLink = {
      provider: providerName,
      providerUserId: profile.id,
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
      profile: profile.raw,
      linkedAt: new Date(),
    };
    await this.adapter.linkOAuthAccount(userId, link);
  }

  /**
   * Find an existing user by their OAuth identity
   */
  async findUserByOAuth(providerName: string, providerUserId: string): Promise<string | null> {
    return this.adapter.findUserByOAuth(providerName, providerUserId);
  }

  /**
   * Unlink an OAuth provider from a user
   */
  async unlinkAccount(userId: string, providerName: string): Promise<boolean> {
    return this.adapter.unlinkOAuthAccount(userId, providerName);
  }

  /**
   * Get all linked OAuth providers for a user
   */
  async getLinkedProviders(userId: string): Promise<OAuthLink[]> {
    return this.adapter.getOAuthLinks(userId);
  }

  // ─── Internal ────────────────────────────────────────────────────────────

  private getProvider(name: string): OAuthProviderConfig {
    const provider = this.providers.get(name);
    if (!provider) {
      throw new OAuthError(`OAuth provider '${name}' is not registered`);
    }
    return provider;
  }

  private async exchangeCode(
    provider: OAuthProviderConfig,
    code: string,
  ): Promise<OAuthTokenResponse> {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: provider.redirectUri,
      client_id: provider.clientId,
      client_secret: provider.clientSecret,
    });

    const response = await fetch(provider.tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: body.toString(),
    });

    if (!response.ok) {
      const text = await response.text();
      throw new OAuthError(`Token exchange failed: ${response.status}`, { body: text });
    }

    return response.json() as Promise<OAuthTokenResponse>;
  }

  private async fetchProfile(
    provider: OAuthProviderConfig,
    accessToken: string,
  ): Promise<OAuthUserProfile> {
    if (!provider.userInfoUrl) {
      throw new OAuthError('Provider does not support user info endpoint');
    }

    const response = await fetch(provider.userInfoUrl, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!response.ok) {
      throw new OAuthError(`Failed to fetch user profile: ${response.status}`);
    }

    const data = (await response.json()) as Record<string, unknown>;
    return provider.mapProfile(data);
  }
}

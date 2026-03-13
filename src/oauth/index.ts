import { OAuthProviderConfig, OAuthUserProfile, OAuthTokenResponse, OAuthProviderPreset, DatabaseAdapter, OAuthLink, KeyValueStore } from '../types/index.js';
import { generateId, generatePKCE } from '../utils/crypto.js';
import { OAuthError } from '../utils/errors.js';
import { createMemoryKeyValueStore } from '../store/index.js';

const PROVIDER_PRESETS: Record<OAuthProviderPreset, Omit<OAuthProviderConfig, 'clientId' | 'clientSecret' | 'redirectUri'>> = {
  google: { authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth', tokenUrl: 'https://oauth2.googleapis.com/token', userInfoUrl: 'https://www.googleapis.com/oauth2/v2/userinfo', scopes: ['openid', 'email', 'profile'], pkce: true, mapProfile: (p) => ({ id: String(p.id), email: String(p.email ?? ''), name: String(p.name ?? ''), avatar: String(p.picture ?? ''), raw: p }) },
  github: { authorizationUrl: 'https://github.com/login/oauth/authorize', tokenUrl: 'https://github.com/login/oauth/access_token', userInfoUrl: 'https://api.github.com/user', scopes: ['read:user', 'user:email'], pkce: false, mapProfile: (p) => ({ id: String(p.id), email: String(p.email ?? ''), name: String(p.name ?? p.login ?? ''), avatar: String(p.avatar_url ?? ''), raw: p }) },
  facebook: { authorizationUrl: 'https://www.facebook.com/v18.0/dialog/oauth', tokenUrl: 'https://graph.facebook.com/v18.0/oauth/access_token', userInfoUrl: 'https://graph.facebook.com/me?fields=id,name,email,picture', scopes: ['email', 'public_profile'], pkce: false, mapProfile: (p) => ({ id: String(p.id), email: String(p.email ?? ''), name: String(p.name ?? ''), avatar: (p.picture as Record<string, Record<string, string>>)?.data?.url ?? '', raw: p }) },
  apple: { authorizationUrl: 'https://appleid.apple.com/auth/authorize', tokenUrl: 'https://appleid.apple.com/auth/token', userInfoUrl: '', scopes: ['name', 'email'], pkce: true, mapProfile: (p) => ({ id: String(p.sub), email: String(p.email ?? ''), name: String(p.name ?? ''), raw: p }) },
  microsoft: { authorizationUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize', tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token', userInfoUrl: 'https://graph.microsoft.com/v1.0/me', scopes: ['openid', 'email', 'profile'], pkce: true, mapProfile: (p) => ({ id: String(p.id), email: String(p.mail ?? p.userPrincipalName ?? ''), name: String(p.displayName ?? ''), raw: p }) },
};

export interface OAuthManager {
  destroy(): void;
  registerPreset(preset: OAuthProviderPreset, config: { clientId: string; clientSecret: string; redirectUri: string; scopes?: string[] }): void;
  registerProvider(name: string, config: OAuthProviderConfig): void;
  getAuthorizationUrl(providerName: string, options?: { state?: string; metadata?: Record<string, unknown> }): Promise<string>;
  handleCallback(providerName: string, code: string, state: string): Promise<{ profile: OAuthUserProfile; tokens: OAuthTokenResponse }>;
  linkAccount(userId: string, providerName: string, profile: OAuthUserProfile, tokens: OAuthTokenResponse): Promise<void>;
  findUserByOAuth(providerName: string, providerUserId: string): Promise<string | null>;
  unlinkAccount(userId: string, providerName: string): Promise<boolean>;
  getLinkedProviders(userId: string): Promise<OAuthLink[]>;
}

export function createOAuthManager(providerConfigs: Record<string, OAuthProviderConfig> = {}, adapter: DatabaseAdapter, externalStateStore?: KeyValueStore): OAuthManager {
  const providers = new Map<string, OAuthProviderConfig>();
  const ownsStateStore = !externalStateStore;
  const stateStore: KeyValueStore & { destroy?(): void } = externalStateStore ?? createMemoryKeyValueStore({ maxEntries: 10_000 });
  for (const [name, cfg] of Object.entries(providerConfigs)) providers.set(name, cfg);

  function getProvider(name: string): OAuthProviderConfig {
    const p = providers.get(name);
    if (!p) throw new OAuthError(`OAuth provider '${name}' is not registered`);
    return p;
  }

  async function exchangeCode(provider: OAuthProviderConfig, code: string, codeVerifier?: string): Promise<OAuthTokenResponse> {
    const params: Record<string, string> = {
      grant_type: 'authorization_code',
      code,
      redirect_uri: provider.redirectUri,
      client_id: provider.clientId,
      client_secret: provider.clientSecret,
    };
    // Include PKCE code_verifier if present
    if (codeVerifier) params.code_verifier = codeVerifier;

    const body = new URLSearchParams(params);
    const response = await fetch(provider.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: body.toString(),
    });
    if (!response.ok) {
      // Don't leak the full response body in production errors
      throw new OAuthError(`Token exchange failed (HTTP ${response.status})`, { provider: provider.clientId });
    }
    return response.json() as Promise<OAuthTokenResponse>;
  }

  async function fetchProfile(provider: OAuthProviderConfig, accessToken: string): Promise<OAuthUserProfile> {
    if (!provider.userInfoUrl) throw new OAuthError('Provider does not support user info endpoint');
    const response = await fetch(provider.userInfoUrl, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!response.ok) throw new OAuthError(`Failed to fetch user profile (HTTP ${response.status})`);
    const data = (await response.json()) as Record<string, unknown>;
    return provider.mapProfile(data);
  }

  return {
    destroy() { if (ownsStateStore && stateStore.destroy) stateStore.destroy(); },

    registerPreset(preset, config) {
      const base = PROVIDER_PRESETS[preset];
      providers.set(preset, { ...base, ...config, scopes: config.scopes ?? base.scopes });
    },

    registerProvider(name, config) { providers.set(name, config); },

    async getAuthorizationUrl(providerName, options = {}) {
      const provider = getProvider(providerName);
      const state = options.state ?? generateId(32);

      // Generate PKCE challenge if provider supports it
      let codeVerifier: string | undefined;
      let codeChallenge: string | undefined;
      let codeChallengeMethod: string | undefined;
      if (provider.pkce !== false) {
        const pkce = generatePKCE();
        codeVerifier = pkce.codeVerifier;
        codeChallenge = pkce.codeChallenge;
        codeChallengeMethod = pkce.codeChallengeMethod;
      }

      // Store state + PKCE verifier
      const stateData = JSON.stringify({
        provider: providerName,
        metadata: options.metadata,
        codeVerifier,
        createdAt: Date.now(),
      });
      await stateStore.set(`oauth_state:${state}`, stateData, 600_000);

      const params: Record<string, string> = {
        client_id: provider.clientId,
        redirect_uri: provider.redirectUri,
        response_type: 'code',
        state,
      };
      if (provider.scopes?.length) params.scope = provider.scopes.join(' ');
      if (codeChallenge) {
        params.code_challenge = codeChallenge;
        params.code_challenge_method = codeChallengeMethod!;
      }

      return `${provider.authorizationUrl}?${new URLSearchParams(params).toString()}`;
    },

    async handleCallback(providerName, code, state) {
      const raw = await stateStore.get(`oauth_state:${state}`);
      if (!raw) throw new OAuthError('Invalid or expired OAuth state', { provider: providerName });

      const stateData = JSON.parse(raw) as { provider: string; codeVerifier?: string; createdAt?: number };
      if (stateData.provider !== providerName) throw new OAuthError('Invalid or expired OAuth state', { provider: providerName });

      // Check state age (max 10 minutes)
      if (stateData.createdAt && Date.now() - stateData.createdAt > 600_000) {
        await stateStore.delete(`oauth_state:${state}`);
        throw new OAuthError('OAuth state has expired', { provider: providerName });
      }

      // Delete state immediately to prevent replay
      await stateStore.delete(`oauth_state:${state}`);

      const provider = getProvider(providerName);
      const tokens = await exchangeCode(provider, code, stateData.codeVerifier);
      const profile = await fetchProfile(provider, tokens.access_token);
      return { profile, tokens };
    },

    async linkAccount(userId, providerName, profile, tokens) {
      const link: OAuthLink = {
        provider: providerName,
        providerUserId: profile.id,
        accessToken: tokens.access_token,
        refreshToken: tokens.refresh_token,
        profile: profile.raw,
        linkedAt: new Date(),
      };
      await adapter.linkOAuthAccount(userId, link);
    },

    async findUserByOAuth(providerName, providerUserId) {
      return adapter.findUserByOAuth(providerName, providerUserId);
    },

    async unlinkAccount(userId, providerName) {
      return adapter.unlinkOAuthAccount(userId, providerName);
    },

    async getLinkedProviders(userId) {
      return adapter.getOAuthLinks(userId);
    },
  };
}

/**
 * LockVault — Social Login / OAuth Example
 *
 * Demonstrates Google and GitHub OAuth with account linking.
 */
import express from 'express';
import { LockVault, MemoryAdapter } from 'lockvault';
import { setAuthCookies } from 'lockvault/middleware/express';

const auth = new LockVault({
  jwt: {
    accessTokenSecret: process.env.JWT_SECRET!,
    refreshTokenSecret: process.env.JWT_REFRESH_SECRET!,
    accessTokenTTL: 900,
    refreshTokenTTL: 604800,
  },
  adapter: new MemoryAdapter(),
});

// ─── Register OAuth Providers ────────────────────────────────────────────

// Use presets for common providers
auth.registerOAuthPreset('google', {
  clientId: process.env.GOOGLE_CLIENT_ID!,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
  redirectUri: 'http://localhost:3000/auth/google/callback',
});

auth.registerOAuthPreset('github', {
  clientId: process.env.GITHUB_CLIENT_ID!,
  clientSecret: process.env.GITHUB_CLIENT_SECRET!,
  redirectUri: 'http://localhost:3000/auth/github/callback',
});

// Or register a custom provider
auth.registerOAuthProvider('discord', {
  clientId: process.env.DISCORD_CLIENT_ID!,
  clientSecret: process.env.DISCORD_CLIENT_SECRET!,
  redirectUri: 'http://localhost:3000/auth/discord/callback',
  authorizationUrl: 'https://discord.com/api/oauth2/authorize',
  tokenUrl: 'https://discord.com/api/oauth2/token',
  userInfoUrl: 'https://discord.com/api/users/@me',
  scopes: ['identify', 'email'],
  mapProfile: (data) => ({
    id: String(data.id),
    email: String(data.email ?? ''),
    name: String(data.username ?? ''),
    avatar: data.avatar
      ? `https://cdn.discordapp.com/avatars/${data.id}/${data.avatar}.png`
      : '',
    raw: data,
  }),
});

// ─── Express App ─────────────────────────────────────────────────────────

const app = express();
app.use(express.json());

// Helper: find or create user by OAuth profile
async function findOrCreateUser(
  provider: string,
  profile: { id: string; email?: string; name?: string },
) {
  // Check if this OAuth identity is already linked
  const existingUserId = await auth.oauth.findUserByOAuth(provider, profile.id);
  if (existingUserId) {
    return existingUserId;
  }

  // Create a new user in your database
  const userId = `user_${Date.now()}`;
  // await db.users.create({ id: userId, email: profile.email, name: profile.name });

  return userId;
}

// ─── OAuth Routes ───────────────────────────────────────────────────────

// Initiate Google login
app.get('/auth/google', (_req, res) => {
  const url = await auth.getOAuthAuthorizationUrl('google');
  res.redirect(url);
});

// Google callback
app.get('/auth/google/callback', async (req, res) => {
  try {
    const { code, state } = req.query as { code: string; state: string };
    const { profile, tokens: oauthTokens } = await auth.handleOAuthCallback('google', code, state);

    // Find or create user
    const userId = await findOrCreateUser('google', profile);

    // Link the OAuth account
    await auth.oauth.linkAccount(userId, 'google', profile, oauthTokens);

    // Create session and JWT tokens
    const { tokens, session } = await auth.login(userId, {
      customClaims: { email: profile.email, name: profile.name, provider: 'google' },
      deviceInfo: { userAgent: req.headers['user-agent'] },
    });

    setAuthCookies(res as any, tokens);
    res.redirect('/dashboard');
  } catch (error: any) {
    console.error('OAuth error:', error);
    res.redirect('/login?error=oauth_failed');
  }
});

// Initiate GitHub login
app.get('/auth/github', (_req, res) => {
  const url = await auth.getOAuthAuthorizationUrl('github');
  res.redirect(url);
});

// GitHub callback
app.get('/auth/github/callback', async (req, res) => {
  try {
    const { code, state } = req.query as { code: string; state: string };
    const { profile, tokens: oauthTokens } = await auth.handleOAuthCallback('github', code, state);

    const userId = await findOrCreateUser('github', profile);
    await auth.oauth.linkAccount(userId, 'github', profile, oauthTokens);

    const { tokens } = await auth.login(userId, {
      customClaims: { email: profile.email, provider: 'github' },
    });

    setAuthCookies(res as any, tokens);
    res.redirect('/dashboard');
  } catch (error: any) {
    console.error('OAuth error:', error);
    res.redirect('/login?error=oauth_failed');
  }
});

// ─── Account Linking (for already-authenticated users) ──────────────────

app.get('/auth/link/github', (req, res) => {
  // Pass current user ID as metadata so we know who to link
  const url = await auth.getOAuthAuthorizationUrl('github', {
    linking: true,
    userId: 'current-user-id', // from session
  } as any);
  res.redirect(url);
});

// View linked accounts
app.get('/api/linked-accounts', async (req, res) => {
  const userId = 'current-user-id'; // from session
  const links = await auth.oauth.getLinkedProviders(userId);
  res.json({
    providers: links.map(l => ({
      provider: l.provider,
      linkedAt: l.linkedAt,
    })),
  });
});

// Unlink an account
app.delete('/api/linked-accounts/:provider', async (req, res) => {
  const userId = 'current-user-id'; // from session
  const success = await auth.oauth.unlinkAccount(userId, req.params.provider);
  res.json({ success });
});

// ─── Start ──────────────────────────────────────────────────────────────

async function start() {
  await auth.initialize();
  app.listen(3000, () => console.log('Server on http://localhost:3000'));
}

start();

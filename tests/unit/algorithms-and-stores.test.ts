import { describe, it, expect, afterEach } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { createJWTManager } from '../../src/jwt/index.js';
import { createMemoryAdapter } from '../../src/adapters/memory/index.js';
import { createMemoryKeyValueStore } from '../../src/store/index.js';
import { safeCompare } from '../../src/utils/crypto.js';
import type { LockVaultConfig } from '../../src/types/index.js';

// ─── ES256 Tests ─────────────────────────────────────────────────────────

describe('ES256 (ECDSA P-256) JWT', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });

  const config: LockVaultConfig = {
    jwt: {
      algorithm: 'ES256',
      accessTokenSecret: '',
      privateKey: privateKey as string,
      publicKey: publicKey as string,
      accessTokenTTL: 900,
    },
    adapter: createMemoryAdapter(),
  };

  it('should sign and verify tokens with ES256', async () => {
    const jwt = createJWTManager(config);
    const pair = await jwt.createTokenPair('user-es256');
    const payload = await jwt.verifyAccessToken(pair.accessToken);
    expect(payload.sub).toBe('user-es256');
  });

  it('should reject tampered ES256 tokens', async () => {
    const jwt = createJWTManager(config);
    const pair = await jwt.createTokenPair('user-es256');
    const tampered = pair.accessToken.slice(0, -5) + 'XXXXX';
    await expect(jwt.verifyAccessToken(tampered)).rejects.toThrow();
  });
});

// ─── EdDSA (Ed25519) Tests ───────────────────────────────────────────────

describe('EdDSA (Ed25519) JWT', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });

  const config: LockVaultConfig = {
    jwt: {
      algorithm: 'EdDSA',
      accessTokenSecret: '',
      privateKey: privateKey as string,
      publicKey: publicKey as string,
      accessTokenTTL: 900,
    },
    adapter: createMemoryAdapter(),
  };

  it('should sign and verify tokens with EdDSA', async () => {
    const jwt = createJWTManager(config);
    const pair = await jwt.createTokenPair('user-eddsa');
    const payload = await jwt.verifyAccessToken(pair.accessToken);
    expect(payload.sub).toBe('user-eddsa');
    expect(payload.type).toBe('access');
  });

  it('should reject tampered EdDSA tokens', async () => {
    const jwt = createJWTManager(config);
    const pair = await jwt.createTokenPair('user-eddsa');
    const tampered = pair.accessToken.slice(0, -5) + 'XXXXX';
    await expect(jwt.verifyAccessToken(tampered)).rejects.toThrow();
  });

  it('should do full refresh token rotation with EdDSA', async () => {
    const jwt = createJWTManager(config);
    const original = await jwt.createTokenPair('user-eddsa');
    const refreshed = await jwt.refreshTokens(original.refreshToken);
    expect(refreshed.accessToken).not.toBe(original.accessToken);

    const payload = await jwt.verifyAccessToken(refreshed.accessToken);
    expect(payload.sub).toBe('user-eddsa');
  });

  it('should reject HS256 tokens when EdDSA is configured', async () => {
    const jwt = createJWTManager(config);

    // Craft a fake HS256 token header
    const fakeHeader = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const fakePayload = Buffer.from(JSON.stringify({ sub: 'attacker' })).toString('base64url');
    const fakeToken = `${fakeHeader}.${fakePayload}.fakesig`;

    await expect(jwt.verifyAccessToken(fakeToken)).rejects.toThrow('Algorithm mismatch');
  });
});

// ─── MemoryKeyValueStore Tests ───────────────────────────────────────────

describe('MemoryKeyValueStore', () => {
  let store: MemoryKeyValueStore;

  afterEach(() => {
    store?.destroy();
  });

  it('should set and get values', async () => {
    store = createMemoryKeyValueStore();
    await store.set('key1', 'value1');
    expect(await store.get('key1')).toBe('value1');
  });

  it('should return null for missing keys', async () => {
    store = createMemoryKeyValueStore();
    expect(await store.get('nonexistent')).toBeNull();
  });

  it('should delete values', async () => {
    store = createMemoryKeyValueStore();
    await store.set('key1', 'value1');
    expect(await store.delete('key1')).toBe(true);
    expect(await store.get('key1')).toBeNull();
  });

  it('should expire values after TTL', async () => {
    store = createMemoryKeyValueStore();
    await store.set('key1', 'value1', 1); // 1ms TTL
    await new Promise(r => setTimeout(r, 10));
    expect(await store.get('key1')).toBeNull();
  });

  it('should keep values within TTL', async () => {
    store = createMemoryKeyValueStore();
    await store.set('key1', 'value1', 60_000); // 60s TTL
    expect(await store.get('key1')).toBe('value1');
  });

  it('should evict when over max entries', async () => {
    store = createMemoryKeyValueStore({ maxEntries: 3 });
    await store.set('a', '1');
    await store.set('b', '2');
    await store.set('c', '3');
    await store.set('d', '4'); // Should evict oldest
    expect(await store.get('d')).toBe('4');
  });
});

// ─── Improved safeCompare Tests ──────────────────────────────────────────

describe('safeCompare (HMAC-based)', () => {
  it('should return true for equal strings', () => {
    expect(safeCompare('hello', 'hello')).toBe(true);
  });

  it('should return false for different strings', () => {
    expect(safeCompare('hello', 'world')).toBe(false);
  });

  it('should return false for different length strings without leaking length', () => {
    // This is the key improvement: previously returned early on length mismatch
    expect(safeCompare('short', 'a-much-longer-string')).toBe(false);
    expect(safeCompare('', 'notempty')).toBe(false);
  });

  it('should handle empty strings', () => {
    expect(safeCompare('', '')).toBe(true);
  });

  it('should work with base64url strings (JWT signatures)', () => {
    const sig = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    expect(safeCompare(sig, sig)).toBe(true);
    expect(safeCompare(sig, sig.slice(0, -1) + 'X')).toBe(false);
  });
});

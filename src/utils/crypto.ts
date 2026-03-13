import { createHmac, randomBytes, createCipheriv, createDecipheriv, timingSafeEqual, scrypt, createHash } from 'node:crypto';
import { LockVaultError, ConfigurationError } from './errors.js';
import { AuthErrorCode } from '../types/index.js';

// Per-process random key for safeCompare — prevents offline precomputation
const PROCESS_COMPARE_KEY = randomBytes(32).toString('hex');

/**
 * Generate a cryptographically secure random string
 */
export function generateId(length: number = 32): string {
  return randomBytes(length).toString('hex');
}

/**
 * Generate a UUID v4
 */
export function generateUUID(): string {
  const bytes = randomBytes(16);
  bytes[6] = (bytes[6]! & 0x0f) | 0x40;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join('-');
}

/**
 * HMAC-SHA256 signing
 */
export function hmacSign(data: string, secret: string): string {
  return createHmac('sha256', secret).update(data).digest('base64url');
}

/**
 * Constant-time comparison of two strings.
 *
 * Uses HMAC comparison with a per-process random key to ensure the execution
 * time is independent of both the content AND the length of the inputs.
 * This prevents timing side-channels that could leak information about
 * expected values, and the random key prevents offline precomputation attacks.
 */
export function safeCompare(a: string, b: string): boolean {
  const hmacA = createHmac('sha256', PROCESS_COMPARE_KEY).update(a).digest();
  const hmacB = createHmac('sha256', PROCESS_COMPARE_KEY).update(b).digest();
  const hmacEqual = timingSafeEqual(hmacA, hmacB);
  const lengthEqual = a.length === b.length;
  return hmacEqual && lengthEqual;
}

/**
 * AES-256-GCM encryption with versioned format for future-proofing.
 */
export function encrypt(plaintext: string, keyHex: string): string {
  if (keyHex.length !== 64) {
    throw new ConfigurationError('Encryption key must be 32 bytes (64 hex characters)');
  }
  const key = Buffer.from(keyHex, 'hex');
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  // Versioned format: version(1) + iv(12) + authTag(16) + ciphertext
  const version = Buffer.from([0x01]);
  return Buffer.concat([version, iv, authTag, encrypted]).toString('base64url');
}

/**
 * AES-256-GCM decryption — supports both v1 (versioned) and legacy formats.
 */
export function decrypt(ciphertext: string, keyHex: string): string {
  if (keyHex.length !== 64) {
    throw new ConfigurationError('Encryption key must be 32 bytes (64 hex characters)');
  }
  try {
    const key = Buffer.from(keyHex, 'hex');
    const data = Buffer.from(ciphertext, 'base64url');

    let iv: Buffer, authTag: Buffer, encrypted: Buffer;
    if (data[0] === 0x01 && data.length > 29) {
      // Versioned format
      iv = data.subarray(1, 13);
      authTag = data.subarray(13, 29);
      encrypted = data.subarray(29);
    } else {
      // Legacy format
      iv = data.subarray(0, 12);
      authTag = data.subarray(12, 28);
      encrypted = data.subarray(28);
    }

    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    return decipher.update(encrypted) + decipher.final('utf8');
  } catch {
    throw new LockVaultError('Failed to decrypt token', AuthErrorCode.ENCRYPTION_ERROR, 401);
  }
}

/**
 * Hash a password using scrypt with hardened parameters.
 *
 * Output format: `scrypt:N:r:p:salt:derivedKey`
 * Embedding the parameters allows future cost upgrades without
 * breaking existing hashes.
 */
export async function hashPassword(password: string, options?: { N?: number; r?: number; p?: number }): Promise<string> {
  const N = options?.N ?? 32768;
  const r = options?.r ?? 8;
  const p = options?.p ?? 2;
  const salt = randomBytes(32).toString('hex');
  const derived = await new Promise<Buffer>((resolve, reject) => {
    scrypt(password, salt, 64, { N, r, p, maxmem: N * r * 256 }, (err, key) => {
      if (err) reject(err);
      else resolve(key);
    });
  });
  return `scrypt:${N}:${r}:${p}:${salt}:${derived.toString('hex')}`;
}

/**
 * Verify a password against its hash.
 * Supports both new format (scrypt:N:r:p:salt:key) and legacy (salt:key).
 */
export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  let salt: string, key: string, N: number, r: number, p: number;

  if (hash.startsWith('scrypt:')) {
    const parts = hash.split(':');
    if (parts.length !== 6) return false;
    N = parseInt(parts[1]!, 10);
    r = parseInt(parts[2]!, 10);
    p = parseInt(parts[3]!, 10);
    salt = parts[4]!;
    key = parts[5]!;
    if (isNaN(N) || isNaN(r) || isNaN(p)) return false;
  } else {
    // Legacy format
    const parts = hash.split(':');
    if (parts.length !== 2) return false;
    salt = parts[0]!;
    key = parts[1]!;
    N = 16384; r = 8; p = 1;
  }

  if (!salt || !key) return false;

  const derived = await new Promise<Buffer>((resolve, reject) => {
    scrypt(password, salt, 64, { N, r, p, maxmem: N * r * 256 }, (err, derivedKey) => {
      if (err) reject(err);
      else resolve(derivedKey);
    });
  });
  return safeCompare(derived.toString('hex'), key);
}

/**
 * Generate backup codes for 2FA
 */
export function generateBackupCodes(count: number = 10): string[] {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    const code = randomBytes(6).toString('hex').toUpperCase();
    codes.push(`${code.slice(0, 4)}-${code.slice(4, 8)}-${code.slice(8, 12)}`);
  }
  return codes;
}

/**
 * Base32 encode (for TOTP secrets)
 */
const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buffer: Buffer): string {
  let result = '';
  let bits = 0;
  let value = 0;
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      result += BASE32_CHARS[(value >>> bits) & 0x1f];
    }
  }
  if (bits > 0) {
    result += BASE32_CHARS[(value << (5 - bits)) & 0x1f];
  }
  return result;
}

/**
 * Base32 decode
 */
export function base32Decode(encoded: string): Buffer {
  const cleaned = encoded.replace(/=+$/, '').toUpperCase();
  const bytes: number[] = [];
  let bits = 0;
  let value = 0;
  for (const char of cleaned) {
    const idx = BASE32_CHARS.indexOf(char);
    if (idx === -1) throw new Error(`Invalid base32 character: ${char}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >>> bits) & 0xff);
    }
  }
  return Buffer.from(bytes);
}

// ─── New Security Utilities ──────────────────────────────────────────────

/**
 * Generate a token fingerprint from client context (IP + User-Agent).
 * Binds tokens to the client that created them, mitigating token theft.
 * Uses a one-way hash so the fingerprint can't be reversed.
 */
export function generateTokenFingerprint(ipAddress?: string, userAgent?: string): string {
  const data = `${ipAddress ?? 'unknown'}|${userAgent ?? 'unknown'}`;
  return createHash('sha256').update(data).digest('base64url').slice(0, 16);
}

/**
 * Validate and sanitize an IP address.
 * Returns the sanitized IP or undefined if invalid.
 */
export function sanitizeIpAddress(ip: string | undefined): string | undefined {
  if (!ip || typeof ip !== 'string') return undefined;

  // Take first IP from comma-separated list (X-Forwarded-For)
  const cleaned = ip.trim().split(',')[0]?.trim();
  if (!cleaned || cleaned.length > 45) return undefined; // Max IPv6 length

  // IPv4
  const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const v4Match = cleaned.match(ipv4Regex);
  if (v4Match) {
    const valid = [v4Match[1], v4Match[2], v4Match[3], v4Match[4]]
      .every(o => parseInt(o!, 10) <= 255);
    return valid ? cleaned : undefined;
  }

  // IPv6 (simplified validation)
  const ipv6Regex = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
  if (ipv6Regex.test(cleaned)) return cleaned;

  // IPv4-mapped IPv6
  const mappedRegex = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i;
  const mappedMatch = cleaned.match(mappedRegex);
  if (mappedMatch) return mappedMatch[1];

  return undefined;
}

/**
 * Generate a PKCE code verifier and challenge pair for OAuth.
 * @see https://datatracker.ietf.org/doc/html/rfc7636
 */
export function generatePKCE(): { codeVerifier: string; codeChallenge: string; codeChallengeMethod: 'S256' } {
  const codeVerifier = randomBytes(32).toString('base64url');
  const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
  return { codeVerifier, codeChallenge, codeChallengeMethod: 'S256' };
}

/**
 * Generate a CSRF token.
 */
export function generateCSRFToken(): string {
  return randomBytes(32).toString('base64url');
}

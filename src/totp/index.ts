import { createHmac, randomBytes } from 'node:crypto';
import { TOTPConfig, TOTPSetupResult, DatabaseAdapter, AuthErrorCode, KeyValueStore } from '../types/index.js';
import { base32Encode, base32Decode, generateBackupCodes, safeCompare } from '../utils/crypto.js';
import { TOTPError } from '../utils/errors.js';
import { createRateLimiter } from '../ratelimit/index.js';
import { createMemoryKeyValueStore } from '../store/index.js';

const DEFAULT_TOTP_CONFIG: Required<TOTPConfig> = { issuer: 'LockVault', algorithm: 'SHA1', digits: 6, period: 30, window: 1 };

export interface TOTPManager {
  setup(userId: string, userEmail?: string): Promise<TOTPSetupResult>;
  confirmSetup(userId: string, secret: string, code: string, backupCodes: string[]): Promise<boolean>;
  verify(userId: string, code: string): Promise<boolean>;
  disable(userId: string): Promise<void>;
  getBackupCodesCount(userId: string): Promise<number>;
  regenerateBackupCodes(userId: string): Promise<string[]>;
  generateCode(secret: string, time?: number): string;
  destroy(): void;
}

export function createTOTPManager(cfg: Partial<TOTPConfig> = {}, adapter: DatabaseAdapter, kvStore?: KeyValueStore): TOTPManager {
  const c: Required<TOTPConfig> = { ...DEFAULT_TOTP_CONFIG, ...cfg };
  const rateLimiter = createRateLimiter({ windowMs: 60_000, maxAttempts: 5 });
  const ownsReplayStore = !kvStore;
  const replayStore: KeyValueStore & { destroy?(): void } = kvStore ?? createMemoryKeyValueStore({ maxEntries: 50_000 });

  function generateSecret(bytes = 20): string { return base32Encode(randomBytes(bytes)); }

  function buildURI(secret: string, accountName: string): string {
    const params = new URLSearchParams({ secret, issuer: c.issuer, algorithm: c.algorithm, digits: String(c.digits), period: String(c.period) });
    const label = `${encodeURIComponent(c.issuer)}:${encodeURIComponent(accountName)}`;
    return `otpauth://totp/${label}?${params.toString()}`;
  }

  function hotpGenerate(secret: string, counter: number): string {
    const key = base32Decode(secret);
    const counterBuffer = Buffer.alloc(8);
    counterBuffer.writeBigUInt64BE(BigInt(counter));
    const algMap: Record<string, string> = { SHA1: 'sha1', SHA256: 'sha256', SHA512: 'sha512' };
    const hmac = createHmac(algMap[c.algorithm]!, key);
    hmac.update(counterBuffer);
    const hash = hmac.digest();
    const offset = hash[hash.length - 1]! & 0x0f;
    const binary = ((hash[offset]! & 0x7f) << 24) | ((hash[offset + 1]! & 0xff) << 16) | ((hash[offset + 2]! & 0xff) << 8) | (hash[offset + 3]! & 0xff);
    const otp = binary % Math.pow(10, c.digits);
    return otp.toString().padStart(c.digits, '0');
  }

  function verifyCode(secret: string, code: string): boolean {
    const now = Math.floor(Date.now() / 1000);
    const counter = Math.floor(now / c.period);
    let valid = false;
    for (let i = -c.window; i <= c.window; i++) {
      const expected = hotpGenerate(secret, counter + i);
      if (expected.length === code.length && safeCompare(expected, code)) valid = true;
    }
    return valid;
  }

  return {
    async setup(userId, userEmail?) {
      const existing = await adapter.getTOTPSecret(userId);
      if (existing) throw new TOTPError('TOTP is already enabled for this user', AuthErrorCode.TOTP_ALREADY_ENABLED);
      const secret = generateSecret();
      const uri = buildURI(secret, userEmail ?? userId);
      const backupCodes = generateBackupCodes(10);
      return { secret, uri, backupCodes };
    },
    async confirmSetup(userId, secret, code, backupCodes) {
      if (!verifyCode(secret, code)) throw new TOTPError('Invalid TOTP code', AuthErrorCode.TOTP_INVALID);
      await adapter.storeTOTPSecret(userId, secret);
      await adapter.storeBackupCodes(userId, backupCodes);
      return true;
    },
    async verify(userId, code) {
      await rateLimiter.consume(`totp:${userId}`);
      const secret = await adapter.getTOTPSecret(userId);
      if (!secret) throw new TOTPError('TOTP is not enabled for this user', AuthErrorCode.TOTP_NOT_ENABLED);
      if (verifyCode(secret, code)) {
        const codeKey = `totp_used:${userId}:${code}`;
        const alreadyUsed = await replayStore.get(codeKey);
        if (alreadyUsed) throw new TOTPError('TOTP code already used', AuthErrorCode.TOTP_INVALID);
        await replayStore.set(codeKey, '1', c.period * (c.window * 2 + 1) * 1000);
        rateLimiter.reset(`totp:${userId}`);
        return true;
      }
      const consumed = await adapter.consumeBackupCode(userId, code);
      if (consumed) { rateLimiter.reset(`totp:${userId}`); return true; }
      throw new TOTPError('Invalid TOTP or backup code', AuthErrorCode.TOTP_INVALID);
    },
    async disable(userId) {
      const secret = await adapter.getTOTPSecret(userId);
      if (!secret) throw new TOTPError('TOTP is not enabled for this user', AuthErrorCode.TOTP_NOT_ENABLED);
      await adapter.removeTOTPSecret(userId);
    },
    async getBackupCodesCount(userId) { return (await adapter.getBackupCodes(userId)).length; },
    async regenerateBackupCodes(userId) {
      const secret = await adapter.getTOTPSecret(userId);
      if (!secret) throw new TOTPError('TOTP is not enabled for this user', AuthErrorCode.TOTP_NOT_ENABLED);
      const codes = generateBackupCodes(10);
      await adapter.storeBackupCodes(userId, codes);
      return codes;
    },
    generateCode(secret, time?) {
      const now = time ?? Math.floor(Date.now() / 1000);
      const counter = Math.floor(now / c.period);
      return hotpGenerate(secret, counter);
    },
    destroy() {
      rateLimiter.destroy();
      if (ownsReplayStore && replayStore.destroy) replayStore.destroy();
    },
  };
}

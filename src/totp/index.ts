import { createHmac, randomBytes } from 'node:crypto';
import {
  TOTPConfig,
  TOTPSetupResult,
  DatabaseAdapter,
  AuthErrorCode,
  KeyValueStore,
} from '../types/index.js';
import { base32Encode, base32Decode, generateBackupCodes, safeCompare } from '../utils/crypto.js';
import { TOTPError } from '../utils/errors.js';
import { RateLimiter } from '../ratelimit/index.js';
import { MemoryKeyValueStore } from '../store/index.js';

const DEFAULT_TOTP_CONFIG: Required<TOTPConfig> = {
  issuer: 'LockVault',
  algorithm: 'SHA1',
  digits: 6,
  period: 30,
  window: 1,
};

export class TOTPManager {
  private readonly config: Required<TOTPConfig>;
  private readonly adapter: DatabaseAdapter;
  private readonly rateLimiter: RateLimiter;
  private readonly replayStore: KeyValueStore;

  constructor(config: Partial<TOTPConfig> = {}, adapter: DatabaseAdapter, kvStore?: KeyValueStore) {
    this.config = { ...DEFAULT_TOTP_CONFIG, ...config };
    this.adapter = adapter;
    this.rateLimiter = new RateLimiter({ windowMs: 60_000, maxAttempts: 5 });
    this.replayStore = kvStore ?? new MemoryKeyValueStore({ maxEntries: 50_000 });
  }

  /**
   * Generate a new TOTP setup for a user (secret + otpauth URI + backup codes)
   */
  async setup(userId: string, userEmail?: string): Promise<TOTPSetupResult> {
    // Check if already enabled
    const existing = await this.adapter.getTOTPSecret(userId);
    if (existing) {
      throw new TOTPError('TOTP is already enabled for this user', AuthErrorCode.TOTP_ALREADY_ENABLED);
    }

    const secret = this.generateSecret();
    const accountName = userEmail ?? userId;
    const uri = this.buildURI(secret, accountName);
    const backupCodes = generateBackupCodes(10);

    return { secret, uri, backupCodes };
  }

  /**
   * Confirm TOTP setup — verify a code, then persist the secret + backup codes
   */
  async confirmSetup(
    userId: string,
    secret: string,
    code: string,
    backupCodes: string[],
  ): Promise<boolean> {
    if (!this.verifyCode(secret, code)) {
      throw new TOTPError('Invalid TOTP code', AuthErrorCode.TOTP_INVALID);
    }

    await this.adapter.storeTOTPSecret(userId, secret);
    await this.adapter.storeBackupCodes(userId, backupCodes);
    return true;
  }

  /**
   * Verify a TOTP code for a user.
   * Rate-limited to 5 attempts per minute per user to prevent brute-force.
   */
  async verify(userId: string, code: string): Promise<boolean> {
    // Enforce rate limit before any verification
    await this.rateLimiter.consume(`totp:${userId}`);

    const secret = await this.adapter.getTOTPSecret(userId);
    if (!secret) {
      throw new TOTPError('TOTP is not enabled for this user', AuthErrorCode.TOTP_NOT_ENABLED);
    }

    if (this.verifyCode(secret, code)) {
      // Replay protection: reject if this exact code was already used
      const codeKey = `totp_used:${userId}:${code}`;
      const alreadyUsed = await this.replayStore.get(codeKey);
      if (alreadyUsed) {
        throw new TOTPError('TOTP code already used', AuthErrorCode.TOTP_INVALID);
      }
      // Mark as used for 2× the period to cover the full time window
      await this.replayStore.set(codeKey, '1', this.config.period * 2 * 1000);

      // Reset rate limit on success
      this.rateLimiter.reset(`totp:${userId}`);
      return true;
    }

    // Try as a backup code
    const consumed = await this.adapter.consumeBackupCode(userId, code);
    if (consumed) {
      this.rateLimiter.reset(`totp:${userId}`);
      return true;
    }

    throw new TOTPError('Invalid TOTP or backup code', AuthErrorCode.TOTP_INVALID);
  }

  /**
   * Disable TOTP for a user
   */
  async disable(userId: string): Promise<void> {
    const secret = await this.adapter.getTOTPSecret(userId);
    if (!secret) {
      throw new TOTPError('TOTP is not enabled for this user', AuthErrorCode.TOTP_NOT_ENABLED);
    }
    await this.adapter.removeTOTPSecret(userId);
  }

  /**
   * Get remaining backup codes count
   */
  async getBackupCodesCount(userId: string): Promise<number> {
    const codes = await this.adapter.getBackupCodes(userId);
    return codes.length;
  }

  /**
   * Regenerate backup codes
   */
  async regenerateBackupCodes(userId: string): Promise<string[]> {
    const secret = await this.adapter.getTOTPSecret(userId);
    if (!secret) {
      throw new TOTPError('TOTP is not enabled for this user', AuthErrorCode.TOTP_NOT_ENABLED);
    }
    const codes = generateBackupCodes(10);
    await this.adapter.storeBackupCodes(userId, codes);
    return codes;
  }

  // ─── Internal Helpers ────────────────────────────────────────────────────

  private generateSecret(bytes: number = 20): string {
    return base32Encode(randomBytes(bytes));
  }

  private buildURI(secret: string, accountName: string): string {
    const params = new URLSearchParams({
      secret,
      issuer: this.config.issuer,
      algorithm: this.config.algorithm,
      digits: String(this.config.digits),
      period: String(this.config.period),
    });
    const label = `${encodeURIComponent(this.config.issuer)}:${encodeURIComponent(accountName)}`;
    return `otpauth://totp/${label}?${params.toString()}`;
  }

  /**
   * Core TOTP code generation (RFC 6238)
   */
  generateCode(secret: string, time?: number): string {
    const now = time ?? Math.floor(Date.now() / 1000);
    const counter = Math.floor(now / this.config.period);
    return this.hotpGenerate(secret, counter);
  }

  /**
   * Verify a TOTP code with time window tolerance.
   * Uses timing-safe comparison to prevent timing attacks.
   */
  private verifyCode(secret: string, code: string): boolean {
    const now = Math.floor(Date.now() / 1000);
    const counter = Math.floor(now / this.config.period);

    // Always check all windows to maintain constant time regardless of which matches
    let valid = false;
    for (let i = -this.config.window; i <= this.config.window; i++) {
      const expected = this.hotpGenerate(secret, counter + i);
      if (expected.length === code.length && safeCompare(expected, code)) {
        valid = true;
      }
    }
    return valid;
  }

  /**
   * HOTP generation (RFC 4226)
   */
  private hotpGenerate(secret: string, counter: number): string {
    const key = base32Decode(secret);
    const counterBuffer = Buffer.alloc(8);
    counterBuffer.writeBigUInt64BE(BigInt(counter));

    const algorithmMap: Record<string, string> = {
      SHA1: 'sha1',
      SHA256: 'sha256',
      SHA512: 'sha512',
    };

    const hmac = createHmac(algorithmMap[this.config.algorithm]!, key);
    hmac.update(counterBuffer);
    const hash = hmac.digest();

    const offset = hash[hash.length - 1]! & 0x0f;
    const binary =
      ((hash[offset]! & 0x7f) << 24) |
      ((hash[offset + 1]! & 0xff) << 16) |
      ((hash[offset + 2]! & 0xff) << 8) |
      (hash[offset + 3]! & 0xff);

    const otp = binary % Math.pow(10, this.config.digits);
    return otp.toString().padStart(this.config.digits, '0');
  }

}

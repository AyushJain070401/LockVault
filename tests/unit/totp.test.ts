import { describe, it, expect, beforeEach } from 'vitest';
import { TOTPManager } from '../../src/totp/index.js';
import { MemoryAdapter } from '../../src/adapters/memory/index.js';
import { TOTPError } from '../../src/utils/errors.js';

describe('TOTPManager', () => {
  let totp: TOTPManager;
  let adapter: MemoryAdapter;

  beforeEach(() => {
    adapter = new MemoryAdapter();
    totp = new TOTPManager({ issuer: 'TestApp', period: 30, window: 1 }, adapter);
  });

  describe('setup', () => {
    it('should generate a TOTP setup with secret, URI, and backup codes', async () => {
      const result = await totp.setup('user-1', 'user@example.com');

      expect(result.secret).toBeDefined();
      expect(result.secret.length).toBeGreaterThan(10);
      expect(result.uri).toContain('otpauth://totp/');
      expect(result.uri).toContain('TestApp');
      expect(result.uri).toContain('user%40example.com');
      expect(result.backupCodes).toHaveLength(10);
      expect(result.backupCodes[0]).toMatch(/^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$/);
    });

    it('should reject setup if TOTP is already enabled', async () => {
      await adapter.storeTOTPSecret('user-1', 'EXISTING_SECRET');

      await expect(totp.setup('user-1')).rejects.toThrow("TOTP");
    });
  });

  describe('confirmSetup', () => {
    it('should confirm with a valid code', async () => {
      const setup = await totp.setup('user-1');
      const code = totp.generateCode(setup.secret);

      const result = await totp.confirmSetup('user-1', setup.secret, code, setup.backupCodes);
      expect(result).toBe(true);

      // Secret should now be stored
      const stored = await adapter.getTOTPSecret('user-1');
      expect(stored).toBe(setup.secret);
    });

    it('should reject with an invalid code', async () => {
      const setup = await totp.setup('user-1');

      await expect(totp.confirmSetup('user-1', setup.secret, '000000', setup.backupCodes))
        .rejects.toThrow("TOTP");
    });
  });

  describe('verify', () => {
    it('should verify a valid TOTP code', async () => {
      const setup = await totp.setup('user-1');
      const code = totp.generateCode(setup.secret);
      await totp.confirmSetup('user-1', setup.secret, code, setup.backupCodes);

      const currentCode = totp.generateCode(setup.secret);
      const result = await totp.verify('user-1', currentCode);
      expect(result).toBe(true);
    });

    it('should verify using a backup code', async () => {
      const setup = await totp.setup('user-1');
      const code = totp.generateCode(setup.secret);
      await totp.confirmSetup('user-1', setup.secret, code, setup.backupCodes);

      const result = await totp.verify('user-1', setup.backupCodes[0]!);
      expect(result).toBe(true);

      // Backup code should be consumed
      const remaining = await totp.getBackupCodesCount('user-1');
      expect(remaining).toBe(9);
    });

    it('should reject an invalid code', async () => {
      const setup = await totp.setup('user-1');
      const code = totp.generateCode(setup.secret);
      await totp.confirmSetup('user-1', setup.secret, code, setup.backupCodes);

      await expect(totp.verify('user-1', '999999')).rejects.toThrow("TOTP");
    });

    it('should throw if TOTP is not enabled', async () => {
      await expect(totp.verify('user-no-totp', '123456')).rejects.toThrow("TOTP");
    });
  });

  describe('disable', () => {
    it('should disable TOTP and remove secrets', async () => {
      const setup = await totp.setup('user-1');
      const code = totp.generateCode(setup.secret);
      await totp.confirmSetup('user-1', setup.secret, code, setup.backupCodes);

      await totp.disable('user-1');

      const stored = await adapter.getTOTPSecret('user-1');
      expect(stored).toBeNull();
    });

    it('should throw if TOTP is not enabled', async () => {
      await expect(totp.disable('user-no-totp')).rejects.toThrow("TOTP");
    });
  });

  describe('regenerateBackupCodes', () => {
    it('should generate new backup codes', async () => {
      const setup = await totp.setup('user-1');
      const code = totp.generateCode(setup.secret);
      await totp.confirmSetup('user-1', setup.secret, code, setup.backupCodes);

      const newCodes = await totp.regenerateBackupCodes('user-1');
      expect(newCodes).toHaveLength(10);
      expect(newCodes).not.toEqual(setup.backupCodes);
    });
  });

  describe('code generation', () => {
    it('should generate consistent codes for same time', () => {
      const secret = 'JBSWY3DPEHPK3PXP'; // well-known test vector
      const time = 59;
      const code1 = totp.generateCode(secret, time);
      const code2 = totp.generateCode(secret, time);
      expect(code1).toBe(code2);
    });

    it('should generate 6-digit codes', () => {
      const setup_secret = 'JBSWY3DPEHPK3PXP';
      const code = totp.generateCode(setup_secret);
      expect(code).toMatch(/^\d{6}$/);
    });
  });
});

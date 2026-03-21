# Changelog

All notable changes to LockVault will be documented in this file.

## [1.1.0] — 2026-03-21

### Fixed
- **Session-JWT family linkage** — `login()` now correctly links the session's `refreshTokenFamily` to the JWT refresh token family. Previously these were independent IDs, making session-family correlation non-functional.
- **TOTP replay window** — Replay-prevention TTL now covers the full TOTP validity window (`period × (window × 2 + 1)`), preventing code reuse at window boundaries.
- **`logout()` error handling** — No longer silently swallows unexpected errors (e.g., database failures). Only ignores expected `LockVaultError` instances for idempotent logout behavior.
- **Malformed JWT payloads** — `verifyToken` now catches JSON parse errors in token payloads and throws a proper `TokenInvalidError` instead of an unhandled exception.
- **AES-256-GCM decryption** — Fixed implicit Buffer-to-string coercion that could corrupt multi-byte characters. Now uses explicit `Buffer.concat()`.
- **IPv6 validation** — `sanitizeIpAddress()` now correctly accepts compressed IPv6 forms like `::1` (loopback) and `fe80::1`.

### Added
- `TOTPManager.destroy()` — Cleans up internal rate limiter and replay store timers to prevent memory leaks.
- `LockVault.close()` now cleans up TOTP timers in addition to OAuth state store.
- New tests: session-JWT linkage, idempotent logout, TOTP replay rejection, malformed payload handling, IPv6 sanitization (176 total tests, up from 166).

### Changed
- `JWTManager.createTokenPair()` now accepts an optional `familyId` parameter for explicit family control.

## [1.0.3] — 2025-06-15

### Added
- Email module with SMTP support and themed templates (login, forgot-password, alert).
- Named template registry for custom email templates.
- Bulk email sending with per-recipient variable interpolation.
- Template engine with `{{#each}}`, `{{#if}}`, `{{#unless}}`, dot-notation, and HTML escaping.
- Custom renderer support (Handlebars, EJS, MJML, React Email).

## [1.0.2] — 2025-06-10

### Added
- EdDSA (Ed25519) algorithm support.
- ES384, ES512 ECDSA support.
- PKCE (Proof Key for Code Exchange) for OAuth providers.
- Refresh token encryption (AES-256-GCM).
- TOTP rate limiting and replay protection.
- Plugin system with lifecycle hooks.
- Key rotation with grace period for previous keys.
- Session absolute timeout and inactivity timeout.
- CSRF protection middleware.

## [1.0.0] — 2025-05-01

### Added
- Initial release.
- JWT token management (HS256, RS256, ES256).
- Session management with multi-device support.
- TOTP/2FA with backup codes.
- OAuth with Google, GitHub, Facebook, Apple, Microsoft presets.
- Memory, PostgreSQL, MongoDB, Redis adapters.
- Express and Fastify middleware.
- Password hashing with scrypt.

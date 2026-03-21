# Contributing to LockVault

Thanks for your interest in contributing! Here's how to get started.

## Development Setup

```bash
git clone https://github.com/AyushJain070401/LockVault.git
cd LockVault
npm install
```

## Commands

```bash
npm test            # Run tests
npm run test:watch  # Run tests in watch mode
npm run typecheck   # Type-check without emitting
npm run build       # Build with tsup
```

## Project Structure

```
src/
├── core/           # createLockVault() factory
├── jwt/            # Token signing, verification, rotation
├── session/        # Session CRUD, timeouts, cleanup
├── totp/           # TOTP/HOTP generation and verification
├── oauth/          # OAuth 2.0 + PKCE, provider presets
├── ratelimit/      # Sliding-window rate limiter
├── store/          # In-memory key-value store
├── email/          # SMTP email with template engine
├── adapters/       # Memory, PostgreSQL, MongoDB, Redis
├── middleware/      # Express and Fastify integrations
├── types/          # All TypeScript interfaces
└── utils/          # Crypto primitives, errors, helpers
```

## Making Changes

1. Fork the repo and create a branch from `main`.
2. Write your code. Add or update tests.
3. Run `npm test` and `npm run typecheck` — both must pass.
4. Open a pull request with a clear description of what changed and why.

## What We're Looking For

- **New database adapters** — Drizzle, Prisma, Turso, DynamoDB, etc.
- **New middleware** — Hono, Koa, Elysia, NestJS, etc.
- **New OAuth presets** — Discord, Slack, LinkedIn, Spotify, etc.
- **Security improvements** — cryptographic hardening, audit findings.
- **Documentation** — examples, guides, typo fixes.
- **Bug fixes** — with a failing test that reproduces the issue.

## Code Style

- TypeScript strict mode, no `any` unless unavoidable.
- Prefer functions over classes.
- Zero runtime dependencies — use `node:crypto` and built-ins only.
- Every public API change needs a test.

## Security Vulnerabilities

If you find a security vulnerability, **please do not open a public issue**.
Email the maintainer directly or use GitHub's private vulnerability reporting.

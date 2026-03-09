/**
 * LockVault — Database Adapter Examples
 *
 * Shows how to use PostgreSQL, MongoDB, and Redis adapters.
 * All adapters use factory functions — no `new` keyword needed.
 */

// ════════════════════════════════════════════════════════════════════════
// PostgreSQL Adapter
// ════════════════════════════════════════════════════════════════════════

import { Pool } from 'pg';
import { createLockVault } from 'lockvault';
import { createPostgresAdapter } from 'lockvault/adapters/postgres';

async function withPostgres() {
  const pool = new Pool({
    host: 'localhost',
    port: 5432,
    database: 'myapp',
    user: 'postgres',
    password: 'password',
    max: 20,
  });

  const adapter = createPostgresAdapter(pool, {
    tablePrefix: 'auth_',  // Tables: auth_sessions, auth_refresh_families, etc.
  });

  const auth = createLockVault({
    jwt: {
      accessTokenSecret: process.env.JWT_SECRET!,
      refreshTokenSecret: process.env.JWT_REFRESH_SECRET!,
    },
    adapter,
  });

  // This creates all tables and indexes
  await auth.initialize();

  // Use auth as normal
  const { tokens } = await auth.login('user-1');
  console.log('Access token:', tokens.accessToken);

  await auth.close(); // Closes the pool
}

// ════════════════════════════════════════════════════════════════════════
// MongoDB Adapter
// ════════════════════════════════════════════════════════════════════════

import { MongoClient } from 'mongodb';
import { createMongoDBAdapter } from 'lockvault/adapters/mongodb';

async function withMongoDB() {
  const client = new MongoClient('mongodb://localhost:27017');
  await client.connect();
  const db = client.db('myapp');

  const adapter = createMongoDBAdapter(db, {
    collectionPrefix: 'auth_',  // Collections: auth_sessions, auth_refresh_families, etc.
  });

  const auth = createLockVault({
    jwt: {
      accessTokenSecret: process.env.JWT_SECRET!,
    },
    adapter,
  });

  // Creates indexes
  await auth.initialize();

  const { tokens } = await auth.login('user-1');
  console.log('Access token:', tokens.accessToken);

  await client.close();
}

// ════════════════════════════════════════════════════════════════════════
// Redis Adapter
// ════════════════════════════════════════════════════════════════════════

import Redis from 'ioredis';
import { createRedisAdapter } from 'lockvault/adapters/redis';

async function withRedis() {
  const redis = new Redis({
    host: 'localhost',
    port: 6379,
    password: process.env.REDIS_PASSWORD,
  });

  const adapter = createRedisAdapter(redis, {
    prefix: 'myapp:auth:',  // Keys: myapp:auth:session:xxx, etc.
  });

  const auth = createLockVault({
    jwt: {
      accessTokenSecret: process.env.JWT_SECRET!,
      accessTokenTTL: 300,    // 5 min access tokens
      refreshTokenTTL: 86400, // 1 day refresh tokens
    },
    adapter,
  });

  await auth.initialize();

  const { tokens } = await auth.login('user-1');
  console.log('Access token:', tokens.accessToken);

  // Redis automatically expires sessions and revocation entries via TTL
  await auth.close();
}

// ════════════════════════════════════════════════════════════════════════
// Custom Adapter (function-based)
// ════════════════════════════════════════════════════════════════════════

import type { DatabaseAdapter, Session, OAuthLink } from 'lockvault';

function createMyCustomAdapter(): DatabaseAdapter {
  // Your internal state (database connections, caches, etc.)
  const sessions = new Map<string, Session>();

  return {
    async createSession(session) {
      sessions.set(session.id, session);
      return session;
    },

    async getSession(sessionId) {
      return sessions.get(sessionId) ?? null;
    },

    // ... implement all other DatabaseAdapter methods
    // See the createMemoryAdapter source for a complete reference

    async getSessionsByUser(_userId) { return []; },
    async updateSession(_id, _updates) { return null; },
    async deleteSession(_id) { return false; },
    async deleteSessionsByUser(_userId) { return 0; },
    async deleteExpiredSessions() { return 0; },
    async storeRefreshTokenFamily(_f, _u, _g) {},
    async getRefreshTokenFamily(_f) { return null; },
    async revokeRefreshTokenFamily(_f) {},
    async incrementRefreshTokenGeneration(_f) { return 0; },
    async addToRevocationList(_jti, _exp) {},
    async isRevoked(_jti) { return false; },
    async cleanupRevocationList() { return 0; },
    async storeTOTPSecret(_u, _s) {},
    async getTOTPSecret(_u) { return null; },
    async removeTOTPSecret(_u) {},
    async storeBackupCodes(_u, _c) {},
    async getBackupCodes(_u) { return []; },
    async consumeBackupCode(_u, _c) { return false; },
    async linkOAuthAccount(_u, _l) {},
    async getOAuthLinks(_u) { return []; },
    async findUserByOAuth(_p, _pid) { return null; },
    async unlinkOAuthAccount(_u, _p) { return false; },
  };
}

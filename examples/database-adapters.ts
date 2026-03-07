/**
 * LockVault — Database Adapter Examples
 *
 * Shows how to use PostgreSQL, MongoDB, and Redis adapters.
 */

// ════════════════════════════════════════════════════════════════════════
// PostgreSQL Adapter
// ════════════════════════════════════════════════════════════════════════

import { Pool } from 'pg';
import { LockVault } from 'lockvault';
import { PostgresAdapter } from 'lockvault/adapters/postgres';

async function withPostgres() {
  const pool = new Pool({
    host: 'localhost',
    port: 5432,
    database: 'myapp',
    user: 'postgres',
    password: 'password',
    max: 20,
  });

  const adapter = new PostgresAdapter(pool, {
    tablePrefix: 'auth_',  // Tables: auth_sessions, auth_refresh_families, etc.
  });

  const auth = new LockVault({
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
import { MongoDBAdapter } from 'lockvault/adapters/mongodb';

async function withMongoDB() {
  const client = new MongoClient('mongodb://localhost:27017');
  await client.connect();
  const db = client.db('myapp');

  const adapter = new MongoDBAdapter(db, {
    collectionPrefix: 'auth_',  // Collections: auth_sessions, auth_refresh_families, etc.
  });

  const auth = new LockVault({
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
import { RedisAdapter } from 'lockvault/adapters/redis';

async function withRedis() {
  const redis = new Redis({
    host: 'localhost',
    port: 6379,
    password: process.env.REDIS_PASSWORD,
  });

  const adapter = new RedisAdapter(redis, {
    prefix: 'myapp:auth:',  // Keys: myapp:auth:session:xxx, etc.
  });

  const auth = new LockVault({
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
// Custom Adapter
// ════════════════════════════════════════════════════════════════════════

import type { DatabaseAdapter, Session, OAuthLink } from 'lockvault';

class MyCustomAdapter implements DatabaseAdapter {
  // Implement all required methods...
  async createSession(session: Session): Promise<Session> {
    // Your custom database logic
    return session;
  }

  async getSession(sessionId: string): Promise<Session | null> {
    // Your custom database logic
    return null;
  }

  // ... implement all other DatabaseAdapter methods
  // See the MemoryAdapter source code for a complete reference implementation

  async getSessionsByUser(_userId: string): Promise<Session[]> { return []; }
  async updateSession(_id: string, _updates: Partial<Session>): Promise<Session | null> { return null; }
  async deleteSession(_id: string): Promise<boolean> { return false; }
  async deleteSessionsByUser(_userId: string): Promise<number> { return 0; }
  async deleteExpiredSessions(): Promise<number> { return 0; }
  async storeRefreshTokenFamily(_f: string, _u: string, _g: number): Promise<void> {}
  async getRefreshTokenFamily(_f: string) { return null; }
  async revokeRefreshTokenFamily(_f: string): Promise<void> {}
  async incrementRefreshTokenGeneration(_f: string): Promise<number> { return 0; }
  async addToRevocationList(_jti: string, _exp: Date): Promise<void> {}
  async isRevoked(_jti: string): Promise<boolean> { return false; }
  async cleanupRevocationList(): Promise<number> { return 0; }
  async storeTOTPSecret(_u: string, _s: string): Promise<void> {}
  async getTOTPSecret(_u: string): Promise<string | null> { return null; }
  async removeTOTPSecret(_u: string): Promise<void> {}
  async storeBackupCodes(_u: string, _c: string[]): Promise<void> {}
  async getBackupCodes(_u: string): Promise<string[]> { return []; }
  async consumeBackupCode(_u: string, _c: string): Promise<boolean> { return false; }
  async linkOAuthAccount(_u: string, _l: OAuthLink): Promise<void> {}
  async getOAuthLinks(_u: string): Promise<OAuthLink[]> { return []; }
  async findUserByOAuth(_p: string, _pid: string): Promise<string | null> { return null; }
  async unlinkOAuthAccount(_u: string, _p: string): Promise<boolean> { return false; }
}

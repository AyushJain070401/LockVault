import { DatabaseAdapter, Session, OAuthLink } from '../../types/index.js';

const SAFE_IDENTIFIER = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

/**
 * PostgreSQL adapter using the `pg` driver.
 *
 * Expects a `pg.Pool` instance. Call `initialize()` to auto-create tables.
 */
export class PostgresAdapter implements DatabaseAdapter {
  private pool: PgPool;
  private tablePrefix: string;

  constructor(pool: PgPool, options: { tablePrefix?: string } = {}) {
    const prefix = options.tablePrefix ?? 'lockvault_';
    if (!SAFE_IDENTIFIER.test(prefix)) {
      throw new Error(`Invalid tablePrefix "${prefix}": must match /^[a-zA-Z_][a-zA-Z0-9_]*$/`);
    }
    this.pool = pool;
    this.tablePrefix = prefix;
  }

  private t(name: string): string {
    return `${this.tablePrefix}${name}`;
  }

  // ─── Lifecycle ─────────────────────────────────────────────────────────

  async initialize(): Promise<void> {
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS ${this.t('sessions')} (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        refresh_token_family TEXT,
        device_info JSONB,
        ip_address TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMPTZ NOT NULL,
        last_active_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
        metadata JSONB
      );
      CREATE INDEX IF NOT EXISTS idx_${this.tablePrefix}sessions_user ON ${this.t('sessions')} (user_id);

      CREATE TABLE IF NOT EXISTS ${this.t('refresh_families')} (
        family TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        generation INTEGER NOT NULL DEFAULT 0,
        revoked BOOLEAN NOT NULL DEFAULT FALSE
      );

      CREATE TABLE IF NOT EXISTS ${this.t('revocation_list')} (
        jti TEXT PRIMARY KEY,
        expires_at TIMESTAMPTZ NOT NULL
      );

      CREATE TABLE IF NOT EXISTS ${this.t('totp_secrets')} (
        user_id TEXT PRIMARY KEY,
        secret TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS ${this.t('backup_codes')} (
        user_id TEXT NOT NULL,
        code TEXT NOT NULL,
        PRIMARY KEY (user_id, code)
      );

      CREATE TABLE IF NOT EXISTS ${this.t('oauth_links')} (
        user_id TEXT NOT NULL,
        provider TEXT NOT NULL,
        provider_user_id TEXT NOT NULL,
        access_token TEXT,
        refresh_token TEXT,
        profile JSONB,
        linked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (user_id, provider)
      );
      CREATE INDEX IF NOT EXISTS idx_${this.tablePrefix}oauth_provider ON ${this.t('oauth_links')} (provider, provider_user_id);
    `);
  }

  async close(): Promise<void> {
    await this.pool.end();
  }

  // ─── Sessions ───────────────────────────────────────────────────────────

  async createSession(session: Session): Promise<Session> {
    await this.pool.query(
      `INSERT INTO ${this.t('sessions')}
        (id, user_id, refresh_token_family, device_info, ip_address, created_at, expires_at, last_active_at, is_revoked, metadata)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [
        session.id, session.userId, session.refreshTokenFamily,
        JSON.stringify(session.deviceInfo ?? null), session.ipAddress ?? null,
        session.createdAt, session.expiresAt, session.lastActiveAt,
        session.isRevoked, JSON.stringify(session.metadata ?? null),
      ],
    );
    return session;
  }

  async getSession(sessionId: string): Promise<Session | null> {
    const { rows } = await this.pool.query(
      `SELECT * FROM ${this.t('sessions')} WHERE id = $1`, [sessionId],
    );
    return rows[0] ? this.mapSession(rows[0]) : null;
  }

  async getSessionsByUser(userId: string): Promise<Session[]> {
    const { rows } = await this.pool.query(
      `SELECT * FROM ${this.t('sessions')} WHERE user_id = $1 ORDER BY created_at DESC`, [userId],
    );
    return rows.map((r: PgRow) => this.mapSession(r));
  }

  async updateSession(sessionId: string, updates: Partial<Session>): Promise<Session | null> {
    const setClauses: string[] = [];
    const values: unknown[] = [];
    let idx = 1;

    if (updates.lastActiveAt !== undefined) {
      setClauses.push(`last_active_at = $${idx++}`);
      values.push(updates.lastActiveAt);
    }
    if (updates.isRevoked !== undefined) {
      setClauses.push(`is_revoked = $${idx++}`);
      values.push(updates.isRevoked);
    }
    if (updates.expiresAt !== undefined) {
      setClauses.push(`expires_at = $${idx++}`);
      values.push(updates.expiresAt);
    }
    if (updates.metadata !== undefined) {
      setClauses.push(`metadata = $${idx++}`);
      values.push(JSON.stringify(updates.metadata));
    }

    if (setClauses.length === 0) return this.getSession(sessionId);

    values.push(sessionId);
    const { rows } = await this.pool.query(
      `UPDATE ${this.t('sessions')} SET ${setClauses.join(', ')} WHERE id = $${idx} RETURNING *`,
      values,
    );
    return rows[0] ? this.mapSession(rows[0]) : null;
  }

  async deleteSession(sessionId: string): Promise<boolean> {
    const { rowCount } = await this.pool.query(
      `DELETE FROM ${this.t('sessions')} WHERE id = $1`, [sessionId],
    );
    return (rowCount ?? 0) > 0;
  }

  async deleteSessionsByUser(userId: string): Promise<number> {
    const { rowCount } = await this.pool.query(
      `DELETE FROM ${this.t('sessions')} WHERE user_id = $1`, [userId],
    );
    return rowCount ?? 0;
  }

  async deleteExpiredSessions(): Promise<number> {
    const { rowCount } = await this.pool.query(
      `DELETE FROM ${this.t('sessions')} WHERE expires_at < NOW() OR is_revoked = TRUE`,
    );
    return rowCount ?? 0;
  }

  // ─── Refresh Token Families ─────────────────────────────────────────────

  async storeRefreshTokenFamily(family: string, userId: string, generation: number): Promise<void> {
    await this.pool.query(
      `INSERT INTO ${this.t('refresh_families')} (family, user_id, generation) VALUES ($1,$2,$3)
       ON CONFLICT (family) DO UPDATE SET user_id=$2, generation=$3, revoked=FALSE`,
      [family, userId, generation],
    );
  }

  async getRefreshTokenFamily(family: string): Promise<{ userId: string; generation: number; revoked: boolean } | null> {
    const { rows } = await this.pool.query(
      `SELECT user_id, generation, revoked FROM ${this.t('refresh_families')} WHERE family = $1`,
      [family],
    );
    if (!rows[0]) return null;
    return { userId: rows[0].user_id as string, generation: rows[0].generation as number, revoked: rows[0].revoked as boolean };
  }

  async revokeRefreshTokenFamily(family: string): Promise<void> {
    await this.pool.query(
      `UPDATE ${this.t('refresh_families')} SET revoked = TRUE WHERE family = $1`, [family],
    );
  }

  async incrementRefreshTokenGeneration(family: string): Promise<number> {
    const { rows } = await this.pool.query(
      `UPDATE ${this.t('refresh_families')} SET generation = generation + 1 WHERE family = $1 RETURNING generation`,
      [family],
    );
    return (rows[0]?.generation as number) ?? 0;
  }

  // ─── Revocation List ────────────────────────────────────────────────────

  async addToRevocationList(jti: string, expiresAt: Date): Promise<void> {
    await this.pool.query(
      `INSERT INTO ${this.t('revocation_list')} (jti, expires_at) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
      [jti, expiresAt],
    );
  }

  async isRevoked(jti: string): Promise<boolean> {
    const { rows } = await this.pool.query(
      `SELECT 1 FROM ${this.t('revocation_list')} WHERE jti = $1`, [jti],
    );
    return rows.length > 0;
  }

  async cleanupRevocationList(): Promise<number> {
    const { rowCount } = await this.pool.query(
      `DELETE FROM ${this.t('revocation_list')} WHERE expires_at < NOW()`,
    );
    return rowCount ?? 0;
  }

  // ─── TOTP ──────────────────────────────────────────────────────────────

  async storeTOTPSecret(userId: string, secret: string): Promise<void> {
    await this.pool.query(
      `INSERT INTO ${this.t('totp_secrets')} (user_id, secret) VALUES ($1,$2)
       ON CONFLICT (user_id) DO UPDATE SET secret=$2`,
      [userId, secret],
    );
  }

  async getTOTPSecret(userId: string): Promise<string | null> {
    const { rows } = await this.pool.query(
      `SELECT secret FROM ${this.t('totp_secrets')} WHERE user_id = $1`, [userId],
    );
    return (rows[0]?.secret as string) ?? null;
  }

  async removeTOTPSecret(userId: string): Promise<void> {
    await this.pool.query('BEGIN');
    try {
      await this.pool.query(`DELETE FROM ${this.t('totp_secrets')} WHERE user_id = $1`, [userId]);
      await this.pool.query(`DELETE FROM ${this.t('backup_codes')} WHERE user_id = $1`, [userId]);
      await this.pool.query('COMMIT');
    } catch (err) {
      await this.pool.query('ROLLBACK');
      throw err;
    }
  }

  async storeBackupCodes(userId: string, codes: string[]): Promise<void> {
    await this.pool.query('BEGIN');
    try {
      await this.pool.query(`DELETE FROM ${this.t('backup_codes')} WHERE user_id = $1`, [userId]);
      if (codes.length > 0) {
        const placeholders = codes.map((_, i) => `($1, $${i + 2})`).join(', ');
        await this.pool.query(
          `INSERT INTO ${this.t('backup_codes')} (user_id, code) VALUES ${placeholders}`,
          [userId, ...codes],
        );
      }
      await this.pool.query('COMMIT');
    } catch (err) {
      await this.pool.query('ROLLBACK');
      throw err;
    }
  }

  async getBackupCodes(userId: string): Promise<string[]> {
    const { rows } = await this.pool.query(
      `SELECT code FROM ${this.t('backup_codes')} WHERE user_id = $1`, [userId],
    );
    return rows.map((r: PgRow) => r.code as string);
  }

  async consumeBackupCode(userId: string, code: string): Promise<boolean> {
    const { rowCount } = await this.pool.query(
      `DELETE FROM ${this.t('backup_codes')} WHERE user_id = $1 AND code = $2`,
      [userId, code.toUpperCase()],
    );
    return (rowCount ?? 0) > 0;
  }

  // ─── OAuth ─────────────────────────────────────────────────────────────

  async linkOAuthAccount(userId: string, link: OAuthLink): Promise<void> {
    await this.pool.query(
      `INSERT INTO ${this.t('oauth_links')}
        (user_id, provider, provider_user_id, access_token, refresh_token, profile, linked_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       ON CONFLICT (user_id, provider) DO UPDATE SET
        provider_user_id=$3, access_token=$4, refresh_token=$5, profile=$6, linked_at=$7`,
      [userId, link.provider, link.providerUserId, link.accessToken ?? null,
       link.refreshToken ?? null, JSON.stringify(link.profile ?? null), link.linkedAt],
    );
  }

  async getOAuthLinks(userId: string): Promise<OAuthLink[]> {
    const { rows } = await this.pool.query(
      `SELECT * FROM ${this.t('oauth_links')} WHERE user_id = $1`, [userId],
    );
    return rows.map((r: PgRow) => ({
      provider: r.provider as string,
      providerUserId: r.provider_user_id as string,
      accessToken: r.access_token as string | undefined,
      refreshToken: r.refresh_token as string | undefined,
      profile: r.profile as Record<string, unknown> | undefined,
      linkedAt: new Date(r.linked_at as string),
    }));
  }

  async findUserByOAuth(provider: string, providerUserId: string): Promise<string | null> {
    const { rows } = await this.pool.query(
      `SELECT user_id FROM ${this.t('oauth_links')} WHERE provider = $1 AND provider_user_id = $2`,
      [provider, providerUserId],
    );
    return (rows[0]?.user_id as string) ?? null;
  }

  async unlinkOAuthAccount(userId: string, provider: string): Promise<boolean> {
    const { rowCount } = await this.pool.query(
      `DELETE FROM ${this.t('oauth_links')} WHERE user_id = $1 AND provider = $2`,
      [userId, provider],
    );
    return (rowCount ?? 0) > 0;
  }

  // ─── Helpers ────────────────────────────────────────────────────────────

  private mapSession(row: PgRow): Session {
    return {
      id: row.id as string,
      userId: row.user_id as string,
      refreshTokenFamily: row.refresh_token_family as string,
      deviceInfo: row.device_info as Session['deviceInfo'],
      ipAddress: row.ip_address as string | undefined,
      createdAt: new Date(row.created_at as string),
      expiresAt: new Date(row.expires_at as string),
      lastActiveAt: new Date(row.last_active_at as string),
      isRevoked: row.is_revoked as boolean,
      metadata: row.metadata as Record<string, unknown> | undefined,
    };
  }
}

// Minimal type for pg.Pool compatibility — avoids hard dependency on @types/pg
interface PgPool {
  query(text: string, values?: unknown[]): Promise<{ rows: PgRow[]; rowCount: number | null }>;
  end(): Promise<void>;
}

type PgRow = Record<string, unknown>;

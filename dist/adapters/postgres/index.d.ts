import { D as DatabaseAdapter } from '../../index-BR3ae_bk.js';

interface PgPool {
    query(text: string, values?: unknown[]): Promise<{
        rows: PgRow[];
        rowCount: number | null;
    }>;
    connect(): Promise<PgClient>;
    end(): Promise<void>;
}
interface PgClient {
    query(text: string, values?: unknown[]): Promise<{
        rows: PgRow[];
        rowCount: number | null;
    }>;
    release(): void;
}
type PgRow = Record<string, unknown>;
/**
 * PostgreSQL adapter using the `pg` driver.
 *
 * Expects a `pg.Pool` instance. Call `initialize()` to auto-create tables.
 */
declare function createPostgresAdapter(pool: PgPool, options?: {
    tablePrefix?: string;
}): DatabaseAdapter;

export { createPostgresAdapter };

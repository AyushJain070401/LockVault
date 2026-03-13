import { D as DatabaseAdapter } from '../../index-BR3ae_bk.js';

interface RedisClient {
    get(key: string): Promise<string | null>;
    set(key: string, value: string, ...args: (string | number)[]): Promise<string | null>;
    del(...keys: string[]): Promise<number>;
    exists(...keys: string[]): Promise<number>;
    sadd(key: string, ...members: string[]): Promise<number>;
    srem(key: string, ...members: string[]): Promise<number>;
    smembers(key: string): Promise<string[]>;
    hset(key: string, field: string, value: string): Promise<number>;
    hmset(key: string, data: Record<string, string>): Promise<string>;
    hgetall(key: string): Promise<Record<string, string>>;
    hincrby(key: string, field: string, increment: number): Promise<number>;
    quit(): Promise<string>;
}
/**
 * Redis adapter using `ioredis`.
 *
 * Uses hash maps and sets for efficient storage. Session and token
 * expiration leverages Redis TTL for automatic cleanup.
 */
declare function createRedisAdapter(redis: RedisClient, options?: {
    prefix?: string;
}): DatabaseAdapter;

export { createRedisAdapter };

import { D as DatabaseAdapter } from '../../index-BN-tpFRY.mjs';

interface MongoDb {
    collection(name: string): MongoCollection;
}
interface MongoCollection {
    createIndex(keys: Record<string, unknown>, options?: Record<string, unknown>): Promise<string>;
    insertOne(doc: unknown): Promise<{
        insertedId: unknown;
    }>;
    insertMany(docs: unknown[]): Promise<{
        insertedCount: number;
    }>;
    findOne(filter: unknown): Promise<MongoDocument | null>;
    find(filter: unknown): MongoCursor;
    findOneAndUpdate(filter: unknown, update: unknown, options?: Record<string, unknown>): Promise<MongoDocument | null>;
    updateOne(filter: unknown, update: unknown, options?: Record<string, unknown>): Promise<{
        modifiedCount: number;
        upsertedCount: number;
    }>;
    deleteOne(filter: unknown): Promise<{
        deletedCount: number;
    }>;
    deleteMany(filter: unknown): Promise<{
        deletedCount: number;
    }>;
}
interface MongoCursor {
    sort(spec: Record<string, number>): MongoCursor;
    toArray(): Promise<MongoDocument[]>;
}
type MongoDocument = Record<string, unknown> & {
    _id: unknown;
};
/**
 * MongoDB adapter using the official `mongodb` driver.
 *
 * Expects a `mongodb.Db` instance. Call `initialize()` to create indexes.
 */
declare function createMongoDBAdapter(db: MongoDb, options?: {
    collectionPrefix?: string;
}): DatabaseAdapter;

export { createMongoDBAdapter };

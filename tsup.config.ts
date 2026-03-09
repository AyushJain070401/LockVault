import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'adapters/postgres/index': 'src/adapters/postgres/index.ts',
    'adapters/mongodb/index': 'src/adapters/mongodb/index.ts',
    'adapters/redis/index': 'src/adapters/redis/index.ts',
    'middleware/express': 'src/middleware/express.ts',
    'middleware/fastify': 'src/middleware/fastify.ts',
    'email/index': 'src/email/index.ts',
  },
  format: ['cjs', 'esm'],
  dts: true,
  splitting: false,
  sourcemap: true,
  clean: true,
  treeshake: true,
  external: ['pg', 'mongodb', 'ioredis', 'nodemailer'],
});

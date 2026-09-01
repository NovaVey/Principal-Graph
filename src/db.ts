/**
 * The one place a connection string is read from the environment. Adapters,
 * views, and tests all get their `Pool` from here instead of each reading
 * `process.env.DATABASE_URL` (or inventing their own default) independently.
 */

import { Pool } from 'pg';

const DEFAULT_CONNECTION_STRING = 'postgresql://postgres:devpass@localhost:5432/principalgraph';

export function createPool(connectionString = process.env.DATABASE_URL): Pool {
  return new Pool({
    connectionString: connectionString ?? DEFAULT_CONNECTION_STRING,
  });
}

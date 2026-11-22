import { mkdirSync } from 'node:fs'
import { resolve } from 'node:path'

const schemaStatements = [
  `CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    full_name TEXT NOT NULL,
    created_at INTEGER NOT NULL
  ) STRICT`,
  `CREATE TABLE IF NOT EXISTS profiles (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    currency TEXT NOT NULL,
    sync_salt TEXT NOT NULL,
    created_at INTEGER NOT NULL
  ) STRICT`,
  'CREATE INDEX IF NOT EXISTS profiles_user_idx ON profiles(user_id, created_at)',
  `CREATE TABLE IF NOT EXISTS otp_challenges (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL COLLATE NOCASE,
    full_name TEXT NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN ('account', 'profile')),
    profile_name TEXT,
    profile_kind TEXT,
    currency TEXT,
    code_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    consumed INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
  ) STRICT`,
  'CREATE INDEX IF NOT EXISTS otp_email_created_idx ON otp_challenges(email, created_at)',
  `CREATE TABLE IF NOT EXISTS access_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL
  ) STRICT`,
  `CREATE TABLE IF NOT EXISTS encrypted_snapshots (
    profile_id TEXT PRIMARY KEY REFERENCES profiles(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL,
    envelope_json TEXT NOT NULL,
    updated_at INTEGER NOT NULL
  ) STRICT`,
]

class LocalSqliteStore {
  constructor(database) {
    this.database = database
    this.initialized = false
  }

  async initialize() {
    if (this.initialized) return
    this.database.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;')
    this.database.exec(`${schemaStatements.join(';\n')};`)
    this.initialized = true
  }

  async get(sql, ...params) {
    return this.database.prepare(sql).get(...params)
  }

  async all(sql, ...params) {
    return this.database.prepare(sql).all(...params)
  }

  async run(sql, ...params) {
    return this.database.prepare(sql).run(...params)
  }

  async transaction(callback) {
    this.database.exec('BEGIN IMMEDIATE')
    try {
      const result = await callback(this)
      this.database.exec('COMMIT')
      return result
    } catch (error) {
      this.database.exec('ROLLBACK')
      throw error
    }
  }

  close() {
    this.database.close()
  }
}

function rowObject(row, columns) {
  if (!row) return undefined
  if (columns?.length) return Object.fromEntries(columns.map((column, index) => [column, row[index]]))
  return Object.fromEntries(Object.entries(row).filter(([key]) => !/^\d+$/.test(key)))
}

class RemoteTursoStore {
  constructor(client, transaction = null) {
    this.client = client
    this.transactionClient = transaction
    this.initialized = Boolean(transaction)
    this.initializePromise = null
  }

  async initialize() {
    if (this.initialized) return
    if (!this.initializePromise) {
      this.initializePromise = (async () => {
        for (const statement of schemaStatements) await this.client.execute(statement)
        this.initialized = true
      })()
    }
    await this.initializePromise
  }

  async #execute(sql, params) {
    const target = this.transactionClient ?? this.client
    return target.execute({ sql, args: params })
  }

  async get(sql, ...params) {
    const result = await this.#execute(sql, params)
    return rowObject(result.rows[0], result.columns)
  }

  async all(sql, ...params) {
    const result = await this.#execute(sql, params)
    return result.rows.map((row) => rowObject(row, result.columns))
  }

  async run(sql, ...params) {
    const result = await this.#execute(sql, params)
    return { changes: result.rowsAffected }
  }

  async transaction(callback) {
    const transaction = await this.client.transaction('write')
    const scopedStore = new RemoteTursoStore(this.client, transaction)
    try {
      const result = await callback(scopedStore)
      await transaction.commit()
      return result
    } catch (error) {
      await transaction.rollback()
      throw error
    }
  }

  close() {
    this.client.close()
  }
}

export async function createStore({ requireRemote = false } = {}) {
  const remoteUrl = process.env.TURSO_DATABASE_URL?.trim()
  const remoteToken = process.env.TURSO_AUTH_TOKEN?.trim()
  if (requireRemote || remoteUrl || remoteToken) {
    if (!remoteUrl || !remoteToken) {
      throw new Error('Set TURSO_DATABASE_URL and TURSO_AUTH_TOKEN for the hosted backend.')
    }
    const { createClient } = await import('@tursodatabase/serverless/compat')
    const client = createClient({ url: remoteUrl, authToken: remoteToken })
    return new RemoteTursoStore(client)
  }

  let DatabaseSync
  try {
    const sqliteMod = await import('node:sqlite')
    DatabaseSync = sqliteMod.DatabaseSync
  } catch {
    throw new Error('Local SQLite is only supported on Node 22.5+. For hosted Vercel, configure TURSO_DATABASE_URL and TURSO_AUTH_TOKEN.')
  }
  const dataDirectory = resolve(process.env.FINGROW_BACKEND_DATA_DIR || './data')
  mkdirSync(dataDirectory, { recursive: true })
  const database = new DatabaseSync(resolve(dataDirectory, 'fingrow-backend.sqlite'))
  return new LocalSqliteStore(database)
}

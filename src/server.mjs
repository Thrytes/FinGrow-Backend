import { createHmac, randomBytes, randomInt, randomUUID, timingSafeEqual } from 'node:crypto'
import { createServer } from 'node:http'
import { createRequire } from 'node:module'
import { createStore } from './database.mjs'

const PORT = Number(process.env.FINGROW_BACKEND_PORT || 4317)
const HOST = process.env.FINGROW_BACKEND_HOST || '127.0.0.1'
const onVercel = Boolean(process.env.VERCEL) || process.env.FINGROW_SERVERLESS === '1'
const BODY_LIMIT = onVercel ? 4 * 1024 * 1024 : 64 * 1024 * 1024
const ENVELOPE_LIMIT = onVercel ? 3 * 1024 * 1024 : BODY_LIMIT
const OTP_TTL_MS = 10 * 60 * 1000
const TOKEN_TTL_MS = 90 * 24 * 60 * 60 * 1000
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
const getOtpSecret = () => process.env.FINGROW_OTP_HASH_SECRET || ''
const getTokenSecret = () => process.env.FINGROW_TOKEN_HASH_SECRET || ''
const allowedOrigins = new Set(
  (process.env.FINGROW_ALLOWED_ORIGINS || 'tauri://localhost,http://tauri.localhost')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean),
)

function ensureSecretsConfigured() {
  if (Buffer.byteLength(getOtpSecret()) < 32 || Buffer.byteLength(getTokenSecret()) < 32) {
    throw Object.assign(
      new Error('Set independent FINGROW_OTP_HASH_SECRET and FINGROW_TOKEN_HASH_SECRET environment variables (at least 32 bytes each) in Vercel settings.'),
      { status: 503 },
    )
  }
}

let storePromise

async function getStore(requireRemote = false) {
  if (!storePromise) {
    storePromise = createStore({ requireRemote }).catch((error) => {
      storePromise = null
      throw error
    })
  }
  return storePromise
}

const require = createRequire(import.meta.url)
let nodemailer
try {
  nodemailer = require('nodemailer')
} catch {
  nodemailer = null
}

const smtpConfigured = Boolean(
  nodemailer &&
    process.env.SMTP_HOST &&
    process.env.SMTP_PORT &&
    process.env.SMTP_USER &&
    process.env.SMTP_PASS &&
    process.env.SMTP_FROM,
)
const mailer = smtpConfigured
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT),
      secure: String(process.env.SMTP_SECURE || 'true').toLowerCase() === 'true',
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
      connectionTimeout: 10_000,
      greetingTimeout: 10_000,
      socketTimeout: 15_000,
      tls: { minVersion: 'TLSv1.2' },
    })
  : null

const json = (response, status, value, extraHeaders = {}) => {
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...extraHeaders,
  })
  response.end(JSON.stringify(value))
}

function setCors(request, response) {
  const origin = request.headers.origin
  if (!origin) return true
  if (!allowedOrigins.has(origin)) return false
  response.setHeader('Access-Control-Allow-Origin', origin)
  response.setHeader('Vary', 'Origin')
  response.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type')
  response.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS')
  response.setHeader('Access-Control-Max-Age', '600')
  return true
}

async function readJson(request) {
  const declaredLength = Number(request.headers['content-length'] || 0)
  if (declaredLength > BODY_LIMIT) throw Object.assign(new Error('Request is too large.'), { status: 413 })
  if (request.body !== undefined && request.body !== null) {
    const body = request.body
    const size = Buffer.byteLength(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body))
    if (size > BODY_LIMIT) throw Object.assign(new Error('Request is too large.'), { status: 413 })
    try {
      const value = typeof body === 'string' || Buffer.isBuffer(body) ? JSON.parse(String(body)) : body
      if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error()
      return value
    } catch {
      throw Object.assign(new Error('Send a valid JSON object.'), { status: 400 })
    }
  }
  const chunks = []
  let length = 0
  for await (const chunk of request) {
    length += chunk.length
    if (length > BODY_LIMIT) throw Object.assign(new Error('Request is too large.'), { status: 413 })
    chunks.push(chunk)
  }
  try {
    const value = JSON.parse(Buffer.concat(chunks).toString('utf8'))
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error()
    return value
  } catch {
    throw Object.assign(new Error('Send a valid JSON object.'), { status: 400 })
  }
}

function cleanEmail(value) {
  return typeof value === 'string' ? value.trim().toLowerCase().slice(0, 254) : ''
}

function cleanText(value, maxLength) {
  return typeof value === 'string' ? value.trim().slice(0, maxLength) : ''
}

function challengeHash(id, code) {
  return createHmac('sha256', getOtpSecret()).update(`${id}:${code}`).digest('hex')
}

function tokenHash(token) {
  return createHmac('sha256', getTokenSecret()).update(token).digest('hex')
}

function safeEqualHex(left, right) {
  if (!/^[0-9a-f]{64}$/i.test(left) || !/^[0-9a-f]{64}$/i.test(right)) return false
  return timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'))
}

async function authUser(request, database) {
  const match = /^Bearer ([A-Za-z0-9_-]{32,128})$/.exec(request.headers.authorization || '')
  if (!match) return null
  const digest = tokenHash(match[1])
  const session = await database.get(`SELECT users.id, users.email, users.full_name
      FROM access_tokens JOIN users ON users.id = access_tokens.user_id
      WHERE access_tokens.token_hash = ? AND access_tokens.expires_at > ?`, digest, Date.now())
  if (!session) return null
  await database.run('UPDATE access_tokens SET last_used_at = ? WHERE token_hash = ?', Date.now(), digest)
  return session
}

async function getProfiles(userId, database) {
  const rows = await database.all(`SELECT id, name, kind, currency, sync_salt, created_at
      FROM profiles WHERE user_id = ? ORDER BY created_at ASC`, userId)
  return rows.map((profile) => ({
      id: profile.id,
      name: profile.name,
      kind: profile.kind,
      currency: profile.currency,
      syncSalt: profile.sync_salt,
      createdAt: new Date(Number(profile.created_at)).toISOString(),
    }))
}

async function issueToken(userId, database) {
  const token = randomBytes(32).toString('base64url')
  const now = Date.now()
  await database.run(
    'INSERT INTO access_tokens (id, user_id, token_hash, expires_at, created_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?)',
    randomUUID(), userId, tokenHash(token), now + TOKEN_TTL_MS, now, now,
  )
  return token
}

async function sendOtp(email, code) {
  if (!mailer) throw Object.assign(new Error('SMTP is not configured on the FinGrow server.'), { status: 503 })
  await mailer.sendMail({
    from: process.env.SMTP_FROM,
    to: email,
    subject: `${code} is your FinGrow verification code`,
    text: `Your FinGrow verification code is ${code}. It expires in 10 minutes. If you did not request it, ignore this email.`,
    html: `<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:32px;color:#10164c"><p style="font-size:12px;letter-spacing:1.5px;color:#6d8196">FINGROW VERIFICATION</p><h1>Confirm your email</h1><p>Enter this one-time code to continue. It expires in 10 minutes.</p><div style="font-size:34px;font-weight:700;letter-spacing:10px;background:#ffFAFA;border:1px solid #dce6f0;border-radius:12px;padding:20px;text-align:center;margin:24px 0">${code}</div><p style="font-size:13px;color:#6d8196">FinGrow will never ask you to share this code.</p></div>`,
  })
}

function profileFromChallenge(challenge, userId, id = randomUUID()) {
  const kind = challenge.profile_kind || 'personal'
  const currency = challenge.currency || 'INR'
  return {
    id,
    userId,
    name: challenge.profile_name || `${challenge.full_name.split(/\s+/)[0]}'s Personal`,
    kind: ['personal', 'household', 'business'].includes(kind) ? kind : 'personal',
    currency: ['INR', 'USD', 'EUR', 'GBP', 'AED', 'SGD'].includes(currency) ? currency : 'INR',
    syncSalt: randomBytes(16).toString('base64'),
    createdAt: Date.now(),
  }
}

async function handleOtpRequest(request, response, database) {
  const body = await readJson(request)
  const email = cleanEmail(body.email)
  const fullName = cleanText(body.fullName, 100)
  const purpose = body.purpose === 'profile' ? 'profile' : 'account'
  const profileName = cleanText(body.profileName, 60)
  const profileKind = cleanText(body.profileKind, 20)
  const currency = cleanText(body.currency, 3).toUpperCase()
  if (!EMAIL_PATTERN.test(email)) return json(response, 400, { error: 'Enter a valid email address.' })
  if (purpose === 'account' && fullName.length < 2) return json(response, 400, { error: 'Enter your full name.' })
  if (purpose === 'profile' && (profileName.length < 2 || !['personal', 'household', 'business'].includes(profileKind))) {
    return json(response, 400, { error: 'Enter a profile name and type.' })
  }
  const requestingUser = purpose === 'profile' ? await authUser(request, database) : null
  if (purpose === 'profile' && !requestingUser) return json(response, 401, { error: 'Sign in before adding a profile.' })
  if (purpose === 'profile' && requestingUser.email.toLowerCase() !== email) {
    return json(response, 403, { error: 'Verify the email address already linked to this account.' })
  }
  const recent = await database.get(
    'SELECT count(*) AS total FROM otp_challenges WHERE email = ? AND created_at > ?',
    email, Date.now() - 15 * 60 * 1000,
  )
  if (Number(recent.total) >= 3) return json(response, 429, { error: 'Too many verification requests. Wait 15 minutes and try again.' })

  const id = randomUUID()
  const code = String(randomInt(100000, 1000000))
  const now = Date.now()
  await database.run('DELETE FROM otp_challenges WHERE created_at < ?', now - 24 * 60 * 60 * 1000)
  await database.run(`INSERT INTO otp_challenges
      (id, email, full_name, purpose, profile_name, profile_kind, currency, code_hash, expires_at, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  id, email, fullName || 'FinGrow user', purpose, profileName || null, profileKind || null, currency || 'INR', challengeHash(id, code), now + OTP_TTL_MS, now)
  try {
    await sendOtp(email, code)
  } catch (error) {
    await database.run('UPDATE otp_challenges SET consumed = 1 WHERE id = ?', id)
    return json(response, error.status || 503, { error: 'The verification email could not be sent. Check server SMTP settings and try again.' })
  }
  return json(response, 200, { challengeId: id, expiresInSeconds: OTP_TTL_MS / 1000 })
}

async function handleOtpVerify(request, response, body, database) {
  const email = cleanEmail(body.email)
  const id = cleanText(body.challengeId, 80)
  const code = typeof body.code === 'string' ? body.code.replace(/\D/g, '') : ''
  if (!EMAIL_PATTERN.test(email) || !id || !/^\d{6}$/.test(code)) {
    return json(response, 400, { error: 'Enter the complete 6-digit verification code.' })
  }

  try {
    const result = await database.transaction(async (transaction) => {
      const challenge = await transaction.get('SELECT * FROM otp_challenges WHERE id = ? AND email = ?', id, email)
      if (!challenge || challenge.consumed || challenge.expires_at <= Date.now() || challenge.attempts >= 5) {
        return { status: 400, body: { error: 'This verification code has expired. Request a new one.' } }
      }
      if (challenge.purpose === 'profile') {
        const requester = await authUser(request, transaction)
        if (!requester || requester.email.toLowerCase() !== email) {
          return { status: 401, body: { error: 'Reconnect this account before verifying a new profile.' } }
        }
      }
      if (!safeEqualHex(challenge.code_hash, challengeHash(id, code))) {
        const attempts = challenge.attempts + 1
        await transaction.run('UPDATE otp_challenges SET attempts = ?, consumed = ? WHERE id = ?', attempts, attempts >= 5 ? 1 : 0, id)
        return {
          status: 400,
          body: { error: attempts >= 5 ? 'Too many incorrect codes. Request a new one.' : 'That code is not correct.' },
        }
      }

      const consumed = await transaction.run('UPDATE otp_challenges SET consumed = 1 WHERE id = ? AND consumed = 0', id)
      if (consumed.changes !== 1) throw new Error('Verification code was already used.')
      let user = await transaction.get('SELECT id, email, full_name FROM users WHERE email = ?', email)
      if (challenge.purpose === 'profile' && !user) throw new Error('Account not found.')
      if (!user) {
        user = { id: randomUUID(), email, full_name: challenge.full_name }
        await transaction.run('INSERT INTO users (id, email, full_name, created_at) VALUES (?, ?, ?, ?)', user.id, user.email, user.full_name, Date.now())
        const profile = profileFromChallenge(challenge, user.id)
        await transaction.run('INSERT INTO profiles (id, user_id, name, kind, currency, sync_salt, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
          profile.id, profile.userId, profile.name, profile.kind, profile.currency, profile.syncSalt, profile.createdAt)
      } else if (challenge.purpose === 'profile') {
        const profile = profileFromChallenge(challenge, user.id, cleanText(body.profileId, 80) || randomUUID())
        await transaction.run('INSERT INTO profiles (id, user_id, name, kind, currency, sync_salt, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
          profile.id, profile.userId, profile.name, profile.kind, profile.currency, profile.syncSalt, profile.createdAt)
      }
      const profiles = await getProfiles(user.id, transaction)
      const token = await issueToken(user.id, transaction)
      return {
        status: 200,
        body: {
          accessToken: token,
          tokenExpiresInSeconds: TOKEN_TTL_MS / 1000,
          user: { id: user.id, email: user.email, fullName: user.full_name },
          profiles,
          activeProfileId: challenge.purpose === 'profile'
            ? profiles.at(-1)?.id
            : profiles[0]?.id,
        },
      }
    })
    return json(response, result.status, result.body)
  } catch (error) {
    console.error('FinGrow OTP verification failed.')
    return json(response, 400, { error: 'Unable to verify this code. Request a new one and try again.' })
  }
}

function validEnvelope(envelope) {
  if (!envelope || typeof envelope !== 'object') return false
  if (envelope.formatVersion !== 1 || typeof envelope.iv !== 'string' || typeof envelope.ciphertext !== 'string') return false
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(envelope.iv) || !/^[A-Za-z0-9+/]+={0,2}$/.test(envelope.ciphertext)) return false
  const iv = Buffer.from(envelope.iv, 'base64')
  const ciphertext = Buffer.from(envelope.ciphertext, 'base64')
  return iv.length === 12 && ciphertext.length >= 16 && ciphertext.length <= ENVELOPE_LIMIT
}

async function route(request, response, database) {
  if (!setCors(request, response)) return json(response, 403, { error: 'This app origin is not allowed.' })
  if (request.method === 'OPTIONS') {
    response.writeHead(204)
    return response.end()
  }
  const url = new URL(request.url || '/', `http://${request.headers.host || 'localhost'}`)
  if (request.method === 'GET' && (url.pathname === '/health' || url.pathname === '/')) {
    return json(response, 200, { ok: true, service: 'fingrow-backend', storage: 'connected', smtpConfigured })
  }
  if (request.method === 'POST' && url.pathname === '/v1/auth/otp/request') {
    return handleOtpRequest(request, response, database)
  }
  if (request.method === 'POST' && url.pathname === '/v1/auth/otp/verify') {
    return handleOtpVerify(request, response, await readJson(request), database)
  }
  if (request.method === 'GET' && url.pathname === '/v1/auth/me') {
    const user = await authUser(request, database)
    if (!user) return json(response, 401, { error: 'Your sync session expired. Verify your email again to reconnect.' })
    return json(response, 200, {
      user: { id: user.id, email: user.email, fullName: user.full_name },
      profiles: await getProfiles(user.id, database),
    })
  }
  if (request.method === 'POST' && url.pathname === '/v1/auth/logout') {
    const match = /^Bearer ([A-Za-z0-9_-]{32,128})$/.exec(request.headers.authorization || '')
    if (match) await database.run('DELETE FROM access_tokens WHERE token_hash = ?', tokenHash(match[1]))
    return json(response, 200, { ok: true })
  }

  const profileRoute = /^\/v1\/profiles\/([A-Za-z0-9_-]{1,80})\/snapshot$/.exec(url.pathname)
  if (profileRoute && (request.method === 'GET' || request.method === 'PUT')) {
    const user = await authUser(request, database)
    if (!user) return json(response, 401, { error: 'Your sync session expired. Verify your email again to reconnect.' })
    const profileId = profileRoute[1]
    const profile = await database.get('SELECT id FROM profiles WHERE id = ? AND user_id = ?', profileId, user.id)
    if (!profile) return json(response, 404, { error: 'Profile not found.' })
    if (request.method === 'GET') {
      const snapshot = await database.get('SELECT revision, envelope_json, updated_at FROM encrypted_snapshots WHERE profile_id = ?', profileId)
      return json(response, 200, snapshot
        ? { revision: Number(snapshot.revision), envelope: JSON.parse(snapshot.envelope_json), updatedAt: new Date(Number(snapshot.updated_at)).toISOString() }
        : { revision: 0, envelope: null, updatedAt: null })
    }

    const body = await readJson(request)
    const expectedRevision = Number(body.expectedRevision)
    if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0 || !validEnvelope(body.envelope)) {
      return json(response, 400, { error: 'The encrypted sync snapshot is invalid.' })
    }
    const result = await database.transaction(async (transaction) => {
      const existing = await transaction.get('SELECT revision FROM encrypted_snapshots WHERE profile_id = ?', profileId)
      const currentRevision = Number(existing?.revision ?? 0)
      if (currentRevision !== expectedRevision) {
        return { status: 409, body: { error: 'A newer encrypted snapshot is available.', revision: currentRevision } }
      }
      const revision = currentRevision + 1
      await transaction.run(`INSERT INTO encrypted_snapshots (profile_id, revision, envelope_json, updated_at)
        VALUES (?, ?, ?, ?) ON CONFLICT(profile_id) DO UPDATE SET
        revision = excluded.revision, envelope_json = excluded.envelope_json, updated_at = excluded.updated_at`,
      profileId, revision, JSON.stringify(body.envelope), Date.now())
      return { status: 200, body: { revision, updatedAt: new Date().toISOString() } }
    })
    return json(response, result.status, result.body)
  }

  return json(response, 404, { error: 'Not found.' })
}

export async function handleBackendRequest(request, response, { requireRemote = false } = {}) {
  try {
    ensureSecretsConfigured()
    const database = await getStore(requireRemote)
    await database.initialize()
    return await route(request, response, database)
  } catch (error) {
    const status = error.status || (String(error.message).includes('TURSO_DATABASE_URL') ? 503 : 500)
    const message = error.message || 'The request could not be completed.'
    if (!response.headersSent) return json(response, status, { error: message })
    response.destroy()
  }
}

if (process.env.FINGROW_SERVERLESS !== '1' && !process.env.VERCEL) {
  const server = createServer((request, response) => {
    void handleBackendRequest(request, response)
  })

  getStore().then((database) => database.initialize()).then(() => {
    server.listen(PORT, HOST, () => {
      console.info(`FinGrow backend listening at http://${HOST}:${PORT}`)
      if (!mailer) console.warn('SMTP is not configured; email verification requests will be rejected.')
    })
  }).catch(() => {
    console.error('FinGrow backend could not initialize storage. Check its database configuration.')
    process.exitCode = 1
  })

  for (const signal of ['SIGINT', 'SIGTERM']) {
    process.on(signal, () => {
      server.close(async () => {
        try { (await getStore()).close() } catch {}
        process.exit(0)
      })
    })
  }
}

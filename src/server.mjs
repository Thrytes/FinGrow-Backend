import { createHmac, randomBytes, randomInt, randomUUID, scryptSync, timingSafeEqual } from 'node:crypto'
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
const defaultOrigins = [
  'tauri://localhost',
  'http://tauri.localhost',
  'https://tauri.localhost',
  'http://localhost',
  'https://localhost',
  'http://127.0.0.1',
]
const envOrigins = (process.env.FINGROW_ALLOWED_ORIGINS || '')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean)
const allowedOrigins = new Set([...defaultOrigins, ...envOrigins])

function ensureSecretsConfigured() {
  if (Buffer.byteLength(getOtpSecret()) < 32 || Buffer.byteLength(getTokenSecret()) < 32) {
    throw Object.assign(
      new Error('Set independent FINGROW_OTP_HASH_SECRET and FINGROW_TOKEN_HASH_SECRET environment variables (at least 32 bytes each) in Vercel settings.'),
      { status: 503 },
    )
  }
}

let storePromise

export async function getStore(requireRemote = false) {
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

const rateLimits = new Map()

function getClientIp(request) {
  const forwarded = request.headers['x-forwarded-for']
  if (typeof forwarded === 'string') {
    return forwarded.split(',')[0].trim()
  }
  return request.socket?.remoteAddress || '127.0.0.1'
}

function checkRateLimit(key, maxRequests, windowMs) {
  const now = Date.now()
  let record = rateLimits.get(key)
  if (!record || record.resetAt <= now) {
    record = { count: 1, resetAt: now + windowMs }
    rateLimits.set(key, record)
    return { ok: true, remaining: maxRequests - 1, resetInSeconds: Math.ceil(windowMs / 1000) }
  }
  if (record.count >= maxRequests) {
    return { ok: false, remaining: 0, resetInSeconds: Math.ceil((record.resetAt - now) / 1000) }
  }
  record.count += 1
  return { ok: true, remaining: maxRequests - record.count, resetInSeconds: Math.ceil((record.resetAt - now) / 1000) }
}

const json = (response, status, value, extraHeaders = {}) => {
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store, no-cache, must-revalidate',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
    'X-Permitted-Cross-Domain-Policies': 'none',
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
    ...extraHeaders,
  })
  response.end(JSON.stringify(value))
}

function setCors(request, response) {
  const origin = request.headers.origin
  if (!origin) return true
  const isAllowed =
    allowedOrigins.has(origin) ||
    /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin) ||
    /^https?:\/\/tauri\.localhost(:\d+)?$/.test(origin)
  if (!isAllowed) return false
  response.setHeader('Access-Control-Allow-Origin', origin)
  response.setHeader('Vary', 'Origin')
  response.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type')
  response.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
  response.setHeader('Access-Control-Max-Age', '600')
  return true
}

async function readJson(request) {
  const declaredLength = Number(request.headers['content-length'] || 0)
  if (declaredLength > BODY_LIMIT) throw Object.assign(new Error('Request is too large.'), { status: 413 })
  if (request.body !== undefined && request.body !== null && request.body !== '') {
    const body = request.body
    if (typeof body === 'object' && !Buffer.isBuffer(body) && !Array.isArray(body)) return body
    try {
      const str = (typeof body === 'string' || Buffer.isBuffer(body) ? String(body) : JSON.stringify(body)).replace(/^\uFEFF/, '').trim()
      const value = JSON.parse(str)
      if (value && typeof value === 'object' && !Array.isArray(value)) return value
    } catch {
      // Continue to stream read fallback
    }
  }
  const chunks = []
  let length = 0
  for await (const chunk of request) {
    length += chunk.length
    if (length > BODY_LIMIT) throw Object.assign(new Error('Request is too large.'), { status: 413 })
    chunks.push(chunk)
  }
  const raw = Buffer.concat(chunks).toString('utf8').replace(/^\uFEFF/, '').trim()
  if (!raw) throw Object.assign(new Error('Send a valid JSON object.'), { status: 400 })
  try {
    const value = JSON.parse(raw)
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

function hashPassword(password) {
  if (typeof password !== 'string' || password.length < 8 || password.length > 128) {
    throw new Error('Password must be between 8 and 128 characters.')
  }
  const salt = randomBytes(16).toString('hex')
  const derivedKey = scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 })
  return `scrypt$${salt}$${derivedKey.toString('hex')}`
}

function verifyPassword(password, stored) {
  if (!stored || typeof stored !== 'string' || !stored.startsWith('scrypt$')) return false
  const parts = stored.split('$')
  if (parts.length !== 3) return false
  const [, salt, hash] = parts
  const derivedKey = scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 })
  const hashBuffer = Buffer.from(hash, 'hex')
  if (derivedKey.length !== hashBuffer.length) return false
  return timingSafeEqual(derivedKey, hashBuffer)
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
  const ip = getClientIp(request)
  const ipLimit = checkRateLimit(`otp-req-ip:${ip}`, 10, 15 * 60 * 1000)
  if (!ipLimit.ok) {
    return json(response, 429, { error: 'Too many verification requests from this network. Wait 15 minutes.' }, { 'Retry-After': String(ipLimit.resetInSeconds) })
  }
  const body = await readJson(request)
  const email = cleanEmail(body.email)
  const emailLimit = checkRateLimit(`otp-req-email:${email}`, 5, 15 * 60 * 1000)
  if (!emailLimit.ok) {
    return json(response, 429, { error: 'Too many verification requests for this email address. Wait 15 minutes.' }, { 'Retry-After': String(emailLimit.resetInSeconds) })
  }
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
  const ip = getClientIp(request)
  const ipLimit = checkRateLimit(`otp-verify-ip:${ip}`, 25, 15 * 60 * 1000)
  if (!ipLimit.ok) {
    return json(response, 429, { error: 'Too many verification attempts from this network. Wait 15 minutes.' }, { 'Retry-After': String(ipLimit.resetInSeconds) })
  }
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
      let user = await transaction.get('SELECT id, email, full_name, password_hash, consented_at FROM users WHERE email = ?', email)
      if (challenge.purpose === 'profile' && !user) throw new Error('Account not found.')

      const rawPassword = typeof body.password === 'string' && body.password.length >= 8 ? body.password : null
      const passwordHash = rawPassword ? hashPassword(rawPassword) : null
      const fullName = cleanText(body.fullName || challenge.full_name, 100) || 'FinGrow user'

      if (!user) {
        user = { id: randomUUID(), email, full_name: fullName, consented_at: null }
        await transaction.run('INSERT INTO users (id, email, full_name, password_hash, created_at) VALUES (?, ?, ?, ?, ?)',
          user.id, user.email, user.full_name, passwordHash, Date.now())
        const profile = profileFromChallenge(challenge, user.id)
        await transaction.run('INSERT INTO profiles (id, user_id, name, kind, currency, sync_salt, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
          profile.id, profile.userId, profile.name, profile.kind, profile.currency, profile.syncSalt, profile.createdAt)
      } else {
        if (passwordHash) {
          await transaction.run('UPDATE users SET password_hash = ? WHERE id = ?', passwordHash, user.id)
        }
        if (challenge.purpose === 'profile') {
          const profile = profileFromChallenge(challenge, user.id, cleanText(body.profileId, 80) || randomUUID())
          await transaction.run('INSERT INTO profiles (id, user_id, name, kind, currency, sync_salt, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
            profile.id, profile.userId, profile.name, profile.kind, profile.currency, profile.syncSalt, profile.createdAt)
        }
      }
      const profiles = await getProfiles(user.id, transaction)
      const token = await issueToken(user.id, transaction)
      return {
        status: 200,
        body: {
          accessToken: token,
          tokenExpiresInSeconds: TOKEN_TTL_MS / 1000,
          user: {
            id: user.id,
            email: user.email,
            fullName: user.full_name,
            consented: Boolean(user.consented_at),
          },
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

async function handleConsent(request, response, body, database) {
  const user = await authUser(request, database)
  if (!user) return json(response, 401, { error: 'Sign in before saving consent.' })
  const version = cleanText(body.version, 40) || '2026.11-v1'
  const consents = body.consents
  if (!consents || typeof consents !== 'object') {
    return json(response, 400, { error: 'Provide consent preferences.' })
  }
  if (!consents.encryptedCloudSync || !consents.localVault) {
    return json(response, 400, { error: 'Essential cloud sync and local vault consents are required to use FinGrow.' })
  }
  const now = Date.now()
  await database.run(
    'UPDATE users SET consented_at = ?, consent_version = ?, consents_json = ? WHERE id = ?',
    now,
    version,
    JSON.stringify(consents),
    user.id,
  )
  return json(response, 200, { ok: true, consentedAt: new Date(now).toISOString() })
}

async function handlePasswordLogin(request, response, body, database) {
  const ip = getClientIp(request)
  const ipLimit = checkRateLimit(`login-ip:${ip}`, 20, 15 * 60 * 1000)
  if (!ipLimit.ok) {
    return json(response, 429, { error: 'Too many login attempts from this network. Wait 15 minutes.' }, { 'Retry-After': String(ipLimit.resetInSeconds) })
  }
  const email = cleanEmail(body.email)
  const password = typeof body.password === 'string' ? body.password : ''
  if (!EMAIL_PATTERN.test(email) || !password || password.length > 128) {
    return json(response, 400, { error: 'Enter your email address and password.' })
  }
  const emailLimit = checkRateLimit(`login-email:${email}`, 10, 15 * 60 * 1000)
  if (!emailLimit.ok) {
    return json(response, 429, { error: 'Too many failed login attempts for this account. Wait 15 minutes.' }, { 'Retry-After': String(emailLimit.resetInSeconds) })
  }
  const user = await database.get('SELECT id, email, full_name, password_hash, consented_at FROM users WHERE email = ?', email)
  if (!user || !user.password_hash || !verifyPassword(password, user.password_hash)) {
    return json(response, 401, { error: 'Incorrect email or password.' })
  }
  const profiles = await getProfiles(user.id, database)
  const token = await issueToken(user.id, database)
  return json(response, 200, {
    accessToken: token,
    tokenExpiresInSeconds: TOKEN_TTL_MS / 1000,
    user: {
      id: user.id,
      email: user.email,
      fullName: user.full_name,
      consented: Boolean(user.consented_at),
    },
    profiles,
    activeProfileId: profiles[0]?.id,
  })
}

async function handleAccountDeletion(request, response, database) {
  const user = await authUser(request, database)
  if (!user) return json(response, 401, { error: 'Sign in to delete your account.' })

  await database.transaction(async (tx) => {
    await tx.run('DELETE FROM encrypted_snapshots WHERE profile_id IN (SELECT id FROM profiles WHERE user_id = ?)', user.id)
    await tx.run('DELETE FROM profiles WHERE user_id = ?', user.id)
    await tx.run('DELETE FROM access_tokens WHERE user_id = ?', user.id)
    await tx.run('DELETE FROM otp_challenges WHERE email = ?', user.email)
    await tx.run('DELETE FROM users WHERE id = ?', user.id)
  })

  return json(response, 200, {
    ok: true,
    message: 'Your account and all associated encrypted cloud data have been permanently erased.',
  })
}

async function handleConsentWithdrawal(request, response, database) {
  const user = await authUser(request, database)
  if (!user) return json(response, 401, { error: 'Sign in to manage consents.' })

  await database.transaction(async (tx) => {
    await tx.run('DELETE FROM encrypted_snapshots WHERE profile_id IN (SELECT id FROM profiles WHERE user_id = ?)', user.id)
    const now = Date.now()
    const withdrawnRecord = JSON.stringify({ withdrawn: true, withdrawnAt: now })
    await tx.run('UPDATE users SET consented_at = NULL, consents_json = ? WHERE id = ?', withdrawnRecord, user.id)
  })

  return json(response, 200, {
    ok: true,
    message: 'Consent has been withdrawn and cloud snapshots have been erased.',
  })
}

async function handleDataExport(request, response, database) {
  const user = await authUser(request, database)
  if (!user) return json(response, 401, { error: 'Sign in to export data.' })

  const profiles = await getProfiles(user.id, database)
  const fullUser = await database.get('SELECT id, email, full_name, consented_at, consent_version, consents_json, created_at FROM users WHERE id = ?', user.id)

  return json(response, 200, {
    format: 'FinGrow Personal Data Export',
    version: '1.0',
    exportedAt: new Date().toISOString(),
    compliance: 'Indian DPDP Act 2023 / GDPR Article 20',
    account: {
      id: fullUser.id,
      email: fullUser.email,
      fullName: fullUser.full_name,
      createdAt: new Date(Number(fullUser.created_at)).toISOString(),
      consentedAt: fullUser.consented_at ? new Date(Number(fullUser.consented_at)).toISOString() : null,
      consentVersion: fullUser.consent_version,
      consents: fullUser.consents_json ? JSON.parse(fullUser.consents_json) : null,
    },
    profiles: profiles.map((p) => ({
      id: p.id,
      name: p.name,
      kind: p.kind,
      currency: p.currency,
      createdAt: new Date(Number(p.createdAt)).toISOString(),
    })),
    note: 'Financial balances and transactions are encrypted on your local device under your master key (Zero-Knowledge Architecture).',
  })
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
  let pathname = url.searchParams.get('__path') || url.pathname
  if (pathname.startsWith('/api/')) {
    pathname = pathname.slice(4)
  }
  pathname = pathname.replace(/\/+$/, '') || '/'
  if (pathname === '/index' || pathname === '') {
    pathname = '/'
  }
  if (request.method === 'GET' && (pathname === '/health' || pathname === '/')) {
    return json(response, 200, { ok: true, service: 'fingrow-backend', storage: 'connected', smtpConfigured })
  }
  if (request.method === 'POST' && pathname === '/v1/auth/otp/request') {
    return handleOtpRequest(request, response, database)
  }
  if (request.method === 'POST' && pathname === '/v1/auth/otp/verify') {
    return handleOtpVerify(request, response, await readJson(request), database)
  }
  if (request.method === 'POST' && pathname === '/v1/auth/login') {
    return handlePasswordLogin(request, response, await readJson(request), database)
  }
  if (request.method === 'POST' && pathname === '/v1/auth/consent') {
    return handleConsent(request, response, await readJson(request), database)
  }
  if (request.method === 'GET' && pathname === '/v1/auth/me') {
    const user = await authUser(request, database)
    if (!user) return json(response, 401, { error: 'Your sync session expired. Verify your email again to reconnect.' })
    return json(response, 200, {
      user: { id: user.id, email: user.email, fullName: user.full_name },
      profiles: await getProfiles(user.id, database),
    })
  }
  if (request.method === 'POST' && pathname === '/v1/auth/logout') {
    const match = /^Bearer ([A-Za-z0-9_-]{32,128})$/.exec(request.headers.authorization || '')
    if (match) await database.run('DELETE FROM access_tokens WHERE token_hash = ?', tokenHash(match[1]))
    return json(response, 200, { ok: true })
  }
  if (request.method === 'DELETE' && (pathname === '/v1/auth/me' || pathname === '/v1/auth/account')) {
    return handleAccountDeletion(request, response, database)
  }
  if (request.method === 'POST' && pathname === '/v1/auth/consent/withdraw') {
    return handleConsentWithdrawal(request, response, database)
  }
  if (request.method === 'GET' && pathname === '/v1/auth/export') {
    return handleDataExport(request, response, database)
  }

  const profileRoute = /^\/v1\/profiles\/([A-Za-z0-9_-]{1,80})\/snapshot$/.exec(pathname)
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

export default async function vercelHandler(request, response) {
  process.env.FINGROW_SERVERLESS = '1'
  return handleBackendRequest(request, response, { requireRemote: true })
}

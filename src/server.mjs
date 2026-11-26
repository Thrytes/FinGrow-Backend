import { createHash, createHmac, randomBytes, randomInt, randomUUID, scrypt, timingSafeEqual } from 'node:crypto'
import { createServer } from 'node:http'
import { createRequire } from 'node:module'
import { promisify } from 'node:util'
import { createStore } from './database.mjs'

const scryptAsync = promisify(scrypt)

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
  if (onVercel) {
    const vercelIp = request.headers['x-real-ip'] || request.headers['x-vercel-forwarded-for']
    if (typeof vercelIp === 'string' && vercelIp.trim()) {
      return vercelIp.split(',')[0].trim()
    }
  }
  const forwarded = request.headers['x-forwarded-for']
  if (typeof forwarded === 'string' && forwarded.trim()) {
    return forwarded.split(',')[0].trim()
  }
  return request.socket?.remoteAddress || '127.0.0.1'
}

function checkMemoryRateLimit(key, maxRequests, windowMs) {
  const now = Date.now()
  if (rateLimits.size > 5000) {
    for (const [entryKey, entry] of rateLimits.entries()) {
      if (entry.resetAt <= now) rateLimits.delete(entryKey)
    }
  }
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

async function checkRateLimit(key, maxRequests, windowMs, database = null) {
  if (!database) return checkMemoryRateLimit(key, maxRequests, windowMs)
  const now = Date.now()
  try {
    return await database.transaction(async (tx) => {
      const existing = await tx.get('SELECT count, reset_at FROM rate_limits WHERE key = ?', key)
      if (!existing || Number(existing.reset_at) <= now) {
        const nextReset = now + windowMs
        await tx.run(
          'INSERT INTO rate_limits (key, count, reset_at) VALUES (?, 1, ?) ON CONFLICT(key) DO UPDATE SET count = 1, reset_at = excluded.reset_at',
          key,
          nextReset,
        )
        return { ok: true, remaining: maxRequests - 1, resetInSeconds: Math.ceil(windowMs / 1000) }
      }
      const currentCount = Number(existing.count)
      const resetAt = Number(existing.reset_at)
      if (currentCount >= maxRequests) {
        return { ok: false, remaining: 0, resetInSeconds: Math.max(1, Math.ceil((resetAt - now) / 1000)) }
      }
      await tx.run('UPDATE rate_limits SET count = ? WHERE key = ?', currentCount + 1, key)
      return { ok: true, remaining: maxRequests - (currentCount + 1), resetInSeconds: Math.max(1, Math.ceil((resetAt - now) / 1000)) }
    })
  } catch {
    return checkMemoryRateLimit(key, maxRequests, windowMs)
  }
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
  const isLocalDesktopOrigin = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)
  const isAllowed =
    allowedOrigins.has(origin) ||
    isLocalDesktopOrigin ||
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

async function hashPassword(password) {
  if (typeof password !== 'string' || password.length < 8 || password.length > 128) {
    throw new Error('Password must be between 8 and 128 characters.')
  }
  const salt = randomBytes(16).toString('hex')
  const derivedKey = await scryptAsync(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 })
  return `scrypt$${salt}$${Buffer.from(derivedKey).toString('hex')}`
}

async function verifyPassword(password, stored) {
  if (!stored || typeof stored !== 'string' || !stored.startsWith('scrypt$')) return false
  const parts = stored.split('$')
  if (parts.length !== 3) return false
  const [, salt, hash] = parts
  if (!/^[0-9a-f]{32}$/i.test(salt) || !/^[0-9a-f]{128}$/i.test(hash)) return false
  const derivedKey = Buffer.from(
    await scryptAsync(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }),
  )
  const hashBuffer = Buffer.from(hash, 'hex')
  if (derivedKey.length !== hashBuffer.length) return false
  return timingSafeEqual(derivedKey, hashBuffer)
}

function hasActiveCloudConsent(user) {
  if (!user || !user.consented_at) return false
  if (!user.consents_json) return false
  try {
    const parsed = JSON.parse(user.consents_json)
    if (parsed?.withdrawn) return false
    return Boolean(parsed?.encryptedCloudSync && parsed?.localVault)
  } catch {
    return false
  }
}

async function authUser(request, database) {
  const match = /^Bearer ([A-Za-z0-9_-]{32,128})$/.exec(request.headers.authorization || '')
  if (!match) return null
  const digest = tokenHash(match[1])
  const session = await database.get(`SELECT users.id, users.email, users.full_name, users.consented_at, users.consents_json
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
  const ipLimit = await checkRateLimit(`otp-req-ip:${ip}`, 10, 15 * 60 * 1000, database)
  if (!ipLimit.ok) {
    return json(response, 429, { error: 'Too many verification requests from this network. Wait 15 minutes.' }, { 'Retry-After': String(ipLimit.resetInSeconds) })
  }
  const body = await readJson(request)
  const email = cleanEmail(body.email)
  const emailLimit = await checkRateLimit(`otp-req-email:${email}`, 5, 15 * 60 * 1000, database)
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
  if (purpose === 'account') {
    const existingAccount = await database.get('SELECT id FROM users WHERE email = ?', email)
    if (existingAccount) {
      return json(response, 409, { error: 'That email is already registered. Sign in instead.' })
    }
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
  const ipLimit = await checkRateLimit(`otp-verify-ip:${ip}`, 25, 15 * 60 * 1000, database)
  if (!ipLimit.ok) {
    return json(response, 429, { error: 'Too many verification attempts from this network. Wait 15 minutes.' }, { 'Retry-After': String(ipLimit.resetInSeconds) })
  }
  const email = cleanEmail(body.email)
  const id = cleanText(body.challengeId, 80)
  const code = typeof body.code === 'string' ? body.code.replace(/\D/g, '') : ''
  if (!EMAIL_PATTERN.test(email) || !id || !/^\d{6}$/.test(code)) {
    return json(response, 400, { error: 'Enter the complete 6-digit verification code.' })
  }

  const rawPassword = typeof body.password === 'string' && body.password.length >= 8 ? body.password : null
  let precomputedPasswordHash = null
  if (rawPassword) {
    if (rawPassword.length > 128) {
      return json(response, 400, { error: 'Password must be between 8 and 128 characters.' })
    }
    precomputedPasswordHash = await hashPassword(rawPassword)
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

      const fullName = cleanText(body.fullName || challenge.full_name, 100) || 'FinGrow user'

      if (!user) {
        if (!precomputedPasswordHash) {
          return { status: 400, body: { error: 'A password between 8 and 128 characters is required to register.' } }
        }
        user = { id: randomUUID(), email, full_name: fullName, consented_at: null }
        await transaction.run('INSERT INTO users (id, email, full_name, password_hash, created_at) VALUES (?, ?, ?, ?, ?)',
          user.id, user.email, user.full_name, precomputedPasswordHash, Date.now())
        const profile = profileFromChallenge(challenge, user.id)
        await transaction.run('INSERT INTO profiles (id, user_id, name, kind, currency, sync_salt, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
          profile.id, profile.userId, profile.name, profile.kind, profile.currency, profile.syncSalt, profile.createdAt)
      } else if (challenge.purpose === 'profile') {
        const profile = profileFromChallenge(challenge, user.id, cleanText(body.profileId, 80) || randomUUID())
        await transaction.run('INSERT INTO profiles (id, user_id, name, kind, currency, sync_salt, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
          profile.id, profile.userId, profile.name, profile.kind, profile.currency, profile.syncSalt, profile.createdAt)
      } else {
        return { status: 409, body: { error: 'That email is already registered. Sign in instead.' } }
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
  const normalizedConsents = {
    transactionalSms: Boolean(consents.transactionalSms),
    encryptedCloudSync: Boolean(consents.encryptedCloudSync),
    localVault: Boolean(consents.localVault),
  }
  await database.run(
    'UPDATE users SET consented_at = ?, consent_version = ?, consents_json = ? WHERE id = ?',
    now,
    version,
    JSON.stringify(normalizedConsents),
    user.id,
  )
  return json(response, 200, { ok: true, consentedAt: new Date(now).toISOString() })
}

async function handlePasswordLogin(request, response, body, database) {
  const ip = getClientIp(request)
  const ipLimit = await checkRateLimit(`login-ip:${ip}`, 20, 15 * 60 * 1000, database)
  if (!ipLimit.ok) {
    return json(response, 429, { error: 'Too many login attempts from this network. Wait 15 minutes.' }, { 'Retry-After': String(ipLimit.resetInSeconds) })
  }
  const email = cleanEmail(body.email)
  const password = typeof body.password === 'string' ? body.password : ''
  if (!EMAIL_PATTERN.test(email) || !password || password.length > 128) {
    return json(response, 400, { error: 'Enter your email address and password.' })
  }
  const emailLimit = await checkRateLimit(`login-email:${email}`, 10, 15 * 60 * 1000, database)
  if (!emailLimit.ok) {
    return json(response, 429, { error: 'Too many failed login attempts for this account. Wait 15 minutes.' }, { 'Retry-After': String(emailLimit.resetInSeconds) })
  }
  const user = await database.get('SELECT id, email, full_name, password_hash, consented_at FROM users WHERE email = ?', email)
  if (!user || !user.password_hash || !(await verifyPassword(password, user.password_hash))) {
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
      createdAt: p.createdAt,
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

const ALLOWED_SCAN_MIME_TYPES = new Set([
  'application/pdf',
  'image/png',
  'image/jpeg',
  'image/webp',
])

function matchesMagicBytes(buffer, mimeType) {
  if (buffer.length < 4) return false
  if (mimeType === 'application/pdf') {
    return buffer.subarray(0, 5).toString('ascii') === '%PDF-'
  }
  if (mimeType === 'image/png') {
    return buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4e && buffer[3] === 0x47
  }
  if (mimeType === 'image/jpeg') {
    return buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff
  }
  if (mimeType === 'image/webp') {
    return (
      buffer.length >= 12 &&
      buffer.subarray(0, 4).toString('ascii') === 'RIFF' &&
      buffer.subarray(8, 12).toString('ascii') === 'WEBP'
    )
  }
  return false
}

function hasUnsafeEmbeddedPayload(buffer, mimeType) {
  if (mimeType !== 'application/pdf') return false
  const sample = buffer.subarray(0, Math.min(buffer.length, 512 * 1024)).toString('latin1')
  return /\/(?:JavaScript|JS|Launch|OpenAction|AA|RichMedia)\b|<script\b/i.test(sample)
}

async function callOllamaJson(prompt, images = null, timeoutMs = 18000) {
  const ollamaUrl = process.env.OLLAMA_BASE_URL || (onVercel ? '' : 'http://127.0.0.1:11434')
  if (!ollamaUrl) return null
  const model = process.env.OLLAMA_MODEL || 'fingro-vl:latest'
  try {
    const payload = { model, prompt, format: 'json', stream: false }
    if (Array.isArray(images) && images.length > 0) {
      payload.images = images
    }
    const res = await fetch(`${ollamaUrl.replace(/\/+$/, '')}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(timeoutMs),
    })
    if (!res.ok) return null
    const data = await res.json()
    if (!data?.response) return null
    return JSON.parse(data.response)
  } catch {
    return null
  }
}

function extractReadablePdfText(buffer) {
  const latin = buffer.subarray(0, Math.min(buffer.length, 2 * 1024 * 1024)).toString('latin1')
  const chunks = []
  let inParen = false
  let escaped = false
  let current = ''
  for (let i = 0; i < latin.length; i++) {
    const ch = latin[i]
    if (escaped) {
      current += ch
      escaped = false
      continue
    }
    if (ch === '\\' && inParen) {
      escaped = true
      continue
    }
    if (ch === '(' && !inParen) {
      inParen = true
      current = ''
      continue
    }
    if (ch === ')' && inParen) {
      inParen = false
      const cleaned = current.replaceAll(/[^\x20-\x7E]/g, ' ').trim()
      if (cleaned.length >= 2) chunks.push(cleaned)
      if (chunks.length >= 1500) break
      continue
    }
    if (inParen && current.length < 240) {
      current += ch
    }
  }
  return chunks.join(' ').slice(0, 14000)
}

function buildDocumentAnalysisPrompt(docKind, fileName, textContext) {
  const schema =
    '{"detectedKind":"cas"|"bank_statement"|"receipt"|"other","accounts":[{"name":string,"institution":string,"type":"bank"|"credit-card"|"cash"|"investment","currency":"INR","balanceMinor":number,"lastFour":string|null}],"transactions":[{"type":"expense"|"income","amountMinor":number,"category":string,"note":string,"occurredAt":string,"accountName":string|null}],"holdings":[{"symbol":string,"name":string,"assetType":"stock"|"mf"|"etf"|"gold"|"bond","quantity":number,"avgPriceMinor":number,"currentPriceMinor":number}],"investmentTransactions":[{"symbol":string,"assetType":"stock"|"mf"|"etf"|"gold"|"bond","action":"buy"|"sell"|"sip"|"dividend","quantity":number,"priceMinor":number,"occurredAt":string}]}'
  const hint =
    docKind === 'cas'
      ? 'This is a CAS / Investment statement. Separate stocks, mutual funds, ETFs, gold, and bonds with quantity, avgPriceMinor, currentPriceMinor (performance), and buy/sell/SIP transactions.'
      : docKind === 'bank_statement'
        ? 'This is a Bank Statement. Extract the bank account details (name, institution, lastFour, ending balanceMinor) and all debit (expense) / credit (income) transactions.'
        : docKind === 'receipt'
          ? 'This is a Receipt or Bill. Extract the merchant, total amountMinor, category, and date as an expense transaction.'
          : 'Auto-detect whether this is a CAS investment statement, bank statement, receipt, or general financial document, and populate the matching arrays.'
  return `You are FinGrowVL, a financial document parser. File: "${cleanText(fileName, 120)}". ${hint} All monetary amounts must be integer minor units (paise/cents, multiply rupees by 100). Return ONLY valid JSON matching: ${schema}.${textContext ? `\n\nDocument text:\n${textContext}` : ''}`
}

async function handleDocumentAnalyze(request, response, body, database) {
  const user = await authUser(request, database)
  const actorKey = user ? user.id : getClientIp(request)
  const limit = await checkRateLimit(`doc-analyze:${actorKey}`, 25, 60 * 60 * 1000, database)
  if (!limit.ok) return json(response, 429, { error: `Too many document analyses. Wait ${limit.resetInSeconds}s.` })

  const fileName = cleanText(body.fileName, 160) || 'document'
  const mimeType = cleanText(body.mimeType, 64).toLowerCase()
  const docKind = cleanText(body.docKind, 24).toLowerCase() || 'auto'
  const base64Content = typeof body.base64Content === 'string' ? body.base64Content.trim() : ''
  const maxBytes = onVercel ? 3 * 1024 * 1024 : 10 * 1024 * 1024
  if (!ALLOWED_REPORT_MIME_TYPES.has(mimeType) || !base64Content) {
    return json(response, 400, { error: 'Upload a valid PDF, image, CSV, TXT, or JSON document.' })
  }
  const buffer = Buffer.from(base64Content, 'base64')
  if (!buffer.length || buffer.length > maxBytes) {
    return json(response, 400, { error: 'Document exceeds the allowed size limit.' })
  }
  if (ALLOWED_SCAN_MIME_TYPES.has(mimeType) && !matchesMagicBytes(buffer, mimeType)) {
    return json(response, 422, { ok: false, safe: false, error: 'File contents do not match its declared file type.' })
  }
  if (hasUnsafeEmbeddedPayload(buffer, mimeType)) {
    return json(response, 422, { ok: false, safe: false, error: 'Document failed security scan (active script or launch action detected).' })
  }

  let textContext = ''
  if (mimeType === 'text/csv' || mimeType === 'text/plain' || mimeType === 'application/json') {
    textContext = buffer.toString('utf8').slice(0, 14000)
  } else if (mimeType === 'application/pdf') {
    textContext = extractReadablePdfText(buffer)
  }

  const isImage = mimeType.startsWith('image/')
  const prompt = buildDocumentAnalysisPrompt(docKind, fileName, textContext)
  const ollamaParsed = await callOllamaJson(prompt, isImage ? [base64Content] : null, 20000)
  const geminiParsed =
    ollamaParsed || (await callGeminiJson(prompt, isImage || mimeType === 'application/pdf' ? { mime_type: mimeType, data: base64Content } : null))

  let modelUsed = ollamaParsed ? 'FinGrowVL' : geminiParsed ? 'gemini' : 'deterministic'
  let extracted = geminiParsed
  if (!extracted && (mimeType === 'text/csv' || mimeType === 'text/plain')) {
    const csv = parseCsvOrTextReport(buffer.toString('utf8'))
    extracted = {
      detectedKind: csv.holdings.length ? 'cas' : 'other',
      accounts: [],
      transactions: [],
      holdings: csv.holdings,
      investmentTransactions: csv.transactions,
    }
  }

  const sha256 = createHash('sha256').update(buffer).digest('hex')
  return json(response, 200, {
    ok: true,
    safe: true,
    sha256,
    modelUsed,
    detectedKind: cleanText(extracted?.detectedKind, 24) || docKind,
    accounts: Array.isArray(extracted?.accounts) ? extracted.accounts.slice(0, 20) : [],
    transactions: Array.isArray(extracted?.transactions) ? extracted.transactions.slice(0, 300) : [],
    holdings: Array.isArray(extracted?.holdings) ? extracted.holdings.slice(0, 200) : [],
    investmentTransactions: Array.isArray(extracted?.investmentTransactions)
      ? extracted.investmentTransactions.slice(0, 300)
      : [],
    scannedAt: new Date().toISOString(),
  })
}

async function callGeminiJson(prompt, inlineData = null) {
  const apiKey = process.env.GEMINI_API_KEY || ''
  if (!apiKey) return null
  const parts = [{ text: prompt }]
  if (inlineData) {
    parts.push({ inline_data: inlineData })
  }
  const res = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${encodeURIComponent(apiKey)}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts }],
        generationConfig: { responseMimeType: 'application/json', temperature: 0.2 },
      }),
      signal: AbortSignal.timeout(8000),
    },
  )
  if (!res.ok) return null
  const data = await res.json()
  const text = data?.candidates?.[0]?.content?.parts?.[0]?.text
  if (!text) return null
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}

async function handleDocumentScan(request, response, body, database) {
  const user = await authUser(request, database)
  if (!user) return json(response, 401, { error: 'Sign in online to scan and upload documents.' })
  const limit = await checkRateLimit(`scan:${user.id}`, 20, 60 * 60 * 1000, database)
  if (!limit.ok) return json(response, 429, { error: `Too many document scans. Wait ${limit.resetInSeconds}s.` })

  const mimeType = cleanText(body.mimeType, 64).toLowerCase()
  const base64Content = typeof body.base64Content === 'string' ? body.base64Content.trim() : ''
  const maxBytes = onVercel ? 3 * 1024 * 1024 : 10 * 1024 * 1024
  if (!ALLOWED_SCAN_MIME_TYPES.has(mimeType) || !base64Content) {
    return json(response, 400, { error: 'Provide a valid PDF, PNG, JPG, or WebP document.' })
  }
  const buffer = Buffer.from(base64Content, 'base64')
  if (!buffer.length || buffer.length > maxBytes) {
    return json(response, 400, { error: 'Document exceeds the allowed scan size limit.' })
  }
  if (!matchesMagicBytes(buffer, mimeType)) {
    return json(response, 422, { ok: false, safe: false, error: 'File contents do not match the declared file type.' })
  }
  if (hasUnsafeEmbeddedPayload(buffer, mimeType)) {
    return json(response, 422, { ok: false, safe: false, error: 'Document failed security scan (active script or launch action detected).' })
  }

  let extracted = null
  if (body.extractReceipt === true && mimeType.startsWith('image/')) {
    extracted = await callGeminiJson(
      'Extract receipt transaction fields as JSON: {"merchant": string|null, "amountMinor": number|null, "currency": "INR"|string, "occurredAt": string|null, "category": string|null}. Amount in minor units (paise/cents). Return null fields if unreadable.',
      { mime_type: mimeType, data: base64Content },
    )
  }

  const sha256 = createHash('sha256').update(buffer).digest('hex')
  return json(response, 200, {
    ok: true,
    safe: true,
    sha256,
    mimeType,
    sizeBytes: buffer.length,
    scannedAt: new Date().toISOString(),
    extracted,
  })
}

function buildDeterministicInsights(metrics) {
  const insights = []
  const income = Math.max(0, Number(metrics.monthlyIncomeMinor) || 0)
  const expense = Math.max(0, Number(metrics.monthlyExpenseMinor) || 0)
  const overdue = Math.max(0, Number(metrics.overdueMinor) || 0)
  const balance = Number(metrics.totalBalanceMinor) || 0

  if (overdue > 0) {
    insights.push({
      title: 'Overdue obligation priority',
      summary: `Clearing overdue dues (${Math.round(overdue / 100)} units) restores full cash-buffer health.`,
      tone: 'warning',
    })
  }
  if (income > 0) {
    const savingsRate = Math.round(((income - expense) / income) * 100)
    insights.push({
      title: savingsRate >= 20 ? 'Healthy monthly savings rate' : 'Tight monthly cash flow',
      summary: `Your recorded monthly surplus is ${savingsRate}% of income across ${Number(metrics.accountCount) || 0} accounts.`,
      tone: savingsRate >= 20 ? 'positive' : 'neutral',
    })
  }
  const top = Array.isArray(metrics.topCategories) ? metrics.topCategories[0] : null
  if (top?.category && expense > 0) {
    const share = Math.round((Number(top.amountMinor || 0) / expense) * 100)
    insights.push({
      title: `${cleanText(top.category, 40)} leads spending`,
      summary: `${cleanText(top.category, 40)} accounts for ${share}% of your recorded expenses (liquid balance: ${Math.round(balance / 100)}).`,
      tone: share >= 45 ? 'warning' : 'neutral',
    })
  }
  if (!insights.length) {
    insights.push({
      title: 'Add activity for deeper AI signals',
      summary: 'Record accounts and recent transactions to unlock personalized cash-flow guidance.',
      tone: 'neutral',
    })
  }
  return insights
}

async function handleAiInsights(request, response, body, database) {
  const user = await authUser(request, database)
  const actorKey = user ? user.id : getClientIp(request)
  const limit = await checkRateLimit(`ai:${actorKey}`, 30, 60 * 60 * 1000, database)
  if (!limit.ok) return json(response, 429, { error: `Too many AI insight requests. Wait ${limit.resetInSeconds}s.` })

  const metrics = {
    currency: cleanText(body.currency, 8) || 'INR',
    totalBalanceMinor: Number(body.totalBalanceMinor) || 0,
    monthlyIncomeMinor: Number(body.monthlyIncomeMinor) || 0,
    monthlyExpenseMinor: Number(body.monthlyExpenseMinor) || 0,
    overdueMinor: Number(body.overdueMinor) || 0,
    accountCount: Number(body.accountCount) || 0,
    cardCount: Number(body.cardCount) || 0,
    topCategories: Array.isArray(body.topCategories) ? body.topCategories.slice(0, 5) : [],
  }

  let source = 'server-rules'
  let insights = null
  const prompt = `Given these anonymized personal finance totals (minor currency units): ${JSON.stringify(metrics)}. Return JSON {"insights":[{"title":string,"summary":string,"tone":"positive"|"neutral"|"warning"}]} with at most 3 concise actionable insights.`
  const ollamaResponse = await callOllamaJson(prompt)
  const aiResponse = ollamaResponse || (await callGeminiJson(prompt))
  if (Array.isArray(aiResponse?.insights) && aiResponse.insights.length) {
    source = ollamaResponse ? 'ollama' : 'gemini'
    insights = aiResponse.insights.slice(0, 3).map((item) => ({
      title: cleanText(item?.title, 80) || 'Insight',
      summary: cleanText(item?.summary, 240) || '',
      tone: ['positive', 'warning', 'neutral'].includes(item?.tone) ? item.tone : 'neutral',
    }))
  } else {
    insights = buildDeterministicInsights(metrics)
  }

  return json(response, 200, { ok: true, source, generatedAt: new Date().toISOString(), insights })
}

function guessSmsCategory(text) {
  const lower = text.toLowerCase()
  if (lower.includes('swiggy') || lower.includes('zomato') || lower.includes('cafe') || lower.includes('restaurant')) return 'Food'
  if (lower.includes('uber') || lower.includes('ola') || lower.includes('metro') || lower.includes('fuel') || lower.includes('petrol')) return 'Transport'
  if (lower.includes('amazon') || lower.includes('flipkart') || lower.includes('mart') || lower.includes('store')) return 'Shopping'
  if (lower.includes('electricity') || lower.includes('bill') || lower.includes('recharge') || lower.includes('broadband')) return 'Bills'
  if (lower.includes('salary') || lower.includes('payroll')) return 'Salary'
  if (lower.includes('upi') || lower.includes('imps') || lower.includes('neft')) return 'Transfer'
  return 'General'
}

function parseSingleTransactionSms(entry, cutoffMs) {
  const body = cleanText(entry?.body, 600)
  const sender = cleanText(entry?.sender, 64)
  if (!body || body.length < 12) return null
  const receivedMs = entry?.receivedAt ? new Date(entry.receivedAt).getTime() : Date.now()
  if (!Number.isFinite(receivedMs) || receivedMs < cutoffMs) return null

  const lower = body.toLowerCase()
  const isDebit = /\b(debited|spent|paid|withdrawn|purchase|sent)\b/.test(lower)
  const isCredit = /\b(credited|received|deposited|refund)\b/.test(lower)
  if (!isDebit && !isCredit) return null

  const amountMatch = /(?:rs\.?|inr|₹)\s*([0-9][0-9,]{0,12}(?:\.[0-9]{1,2})?)/i.exec(body)
  if (!amountMatch) return null
  const amountValue = Number(amountMatch[1].replaceAll(',', ''))
  if (!Number.isFinite(amountValue) || amountValue <= 0) return null

  const amountMinor = Math.round(amountValue * 100)
  const acctMatch = /(?:a\/c|acct|account|card)\s*(?:no\.?\s*)?[xX*]*([0-9]{4})/i.exec(body)
  const occurredAt = new Date(receivedMs).toISOString()
  const referenceId = createHash('sha256')
    .update(`${sender}:${occurredAt}:${amountMinor}:${body.slice(0, 60)}`)
    .digest('hex')
    .slice(0, 16)

  return {
    referenceId,
    type: isDebit && !isCredit ? 'expense' : 'income',
    amountMinor,
    currency: 'INR',
    accountHint: acctMatch ? acctMatch[1] : null,
    sender: sender || 'Bank SMS',
    category: guessSmsCategory(body),
    occurredAt,
  }
}

async function handleMobileSmsParse(request, response, body, database) {
  const user = await authUser(request, database)
  if (!user) return json(response, 401, { error: 'Sign in to parse transactional SMS.' })
  const limit = await checkRateLimit(`sms:${user.id}`, 30, 60 * 60 * 1000, database)
  if (!limit.ok) return json(response, 429, { error: `Too many SMS parse requests. Wait ${limit.resetInSeconds}s.` })

  const messages = Array.isArray(body.messages) ? body.messages.slice(0, 200) : []
  const cutoffMs = Date.now() - 7 * 24 * 60 * 60 * 1000
  const parsed = []
  let skippedCount = 0
  for (const entry of messages) {
    const item = parseSingleTransactionSms(entry, cutoffMs)
    if (item) parsed.push(item)
    else skippedCount += 1
  }
  return json(response, 200, { ok: true, parsed, skippedCount })
}

const MARKET_CACHE_TTL_MS = 5 * 60 * 1000
const marketQuoteCache = new Map()
const ALLOWED_REPORT_MIME_TYPES = new Set([
  'application/pdf',
  'text/csv',
  'text/plain',
  'application/json',
  'image/png',
  'image/jpeg',
  'image/webp',
])

function toYahooSymbol(symbol, exchange = '') {
  const clean = cleanText(symbol, 40).toUpperCase()
  if (!clean) return ''
  if (clean.includes('.') || clean.includes('=')) return clean
  const ex = cleanText(exchange, 16).toUpperCase()
  if (ex === 'NSE' || clean.endsWith(':NSE')) return `${clean.replace(':NSE', '')}.NS`
  if (ex === 'BSE' || clean.endsWith(':BSE')) return `${clean.replace(':BSE', '')}.BO`
  if (clean.includes(':')) return clean.split(':')[0]
  return clean
}

function inferAssetTypeFromQuote(item) {
  const type = String(item?.quoteType || '').toUpperCase()
  const name = String(item?.shortname || item?.longname || '').toLowerCase()
  if (name.includes('gold')) return 'gold'
  if (type === 'ETF') return 'etf'
  if (type === 'MUTUALFUND') return 'mf'
  if (name.includes('bond') || name.includes('g-sec') || name.includes('treasury')) return 'bond'
  return 'stock'
}

async function fetchYahooQuote(yahooSymbol) {
  const res = await fetch(
    `https://query1.finance.yahoo.com/v8/finance/chart/${encodeURIComponent(yahooSymbol)}?interval=1d&range=2d`,
    {
      headers: { 'User-Agent': 'FinGrow/1.0', Accept: 'application/json' },
      signal: AbortSignal.timeout(5000),
    },
  )
  if (!res.ok) return null
  const data = await res.json()
  const meta = data?.chart?.result?.[0]?.meta
  const price = Number(meta?.regularMarketPrice)
  if (!Number.isFinite(price) || price <= 0) return null
  const prevClose = Number(meta?.chartPreviousClose || meta?.previousClose || price)
  const changePct = prevClose > 0 ? Number((((price - prevClose) / prevClose) * 100).toFixed(2)) : 0
  return {
    priceMinor: Math.round(price * 100),
    previousCloseMinor: Math.round(prevClose * 100),
    changePct,
    currency: cleanText(meta?.currency, 8) || 'INR',
    quoteType: meta?.marketState === 'REGULAR' ? 'live' : 'eod',
    effectiveAt: meta?.regularMarketTime
      ? new Date(Number(meta.regularMarketTime) * 1000).toISOString()
      : new Date().toISOString(),
    source: 'yahoo',
  }
}

async function fetchMfNav(schemeCode) {
  const res = await fetch(`https://api.mfapi.in/mf/${encodeURIComponent(String(schemeCode))}/latest`, {
    headers: { Accept: 'application/json' },
    signal: AbortSignal.timeout(5000),
  })
  if (!res.ok) return null
  const data = await res.json()
  const latest = Array.isArray(data?.data) ? data.data[0] : null
  const nav = Number(latest?.nav)
  if (!Number.isFinite(nav) || nav <= 0) return null
  return {
    priceMinor: Math.round(nav * 100),
    previousCloseMinor: Math.round(nav * 100),
    changePct: 0,
    currency: 'INR',
    quoteType: 'eod',
    effectiveAt: new Date().toISOString(),
    source: 'mfapi',
  }
}

async function handleMarketSearch(request, response, url, database) {
  const user = await authUser(request, database)
  const actorKey = user ? user.id : getClientIp(request)
  const limit = await checkRateLimit(`market-search:${actorKey}`, 60, 60 * 60 * 1000, database)
  if (!limit.ok) return json(response, 429, { error: `Too many market searches. Wait ${limit.resetInSeconds}s.` })

  const query = cleanText(url.searchParams.get('q'), 80)
  const kind = cleanText(url.searchParams.get('kind'), 16).toLowerCase() || 'all'
  if (query.length < 2) return json(response, 200, { ok: true, results: [] })

  const results = []
  const wantYahoo = kind === 'all' || kind === 'stock' || kind === 'etf' || kind === 'gold' || kind === 'bond'
  const wantMf = kind === 'all' || kind === 'mf'

  const tasks = []
  if (wantYahoo) {
    tasks.push(
      fetch(
        `https://query1.finance.yahoo.com/v1/finance/search?q=${encodeURIComponent(query)}&quotesCount=8&newsCount=0`,
        { headers: { 'User-Agent': 'FinGrow/1.0', Accept: 'application/json' }, signal: AbortSignal.timeout(5000) },
      )
        .then((res) => (res.ok ? res.json() : null))
        .then((data) => {
          const quotes = Array.isArray(data?.quotes) ? data.quotes : []
          for (const item of quotes.slice(0, 8)) {
            if (!item?.symbol) continue
            const assetType = inferAssetTypeFromQuote(item)
            if (kind !== 'all' && kind !== assetType) continue
            results.push({
              symbol: String(item.symbol),
              name: cleanText(item.shortname || item.longname || item.symbol, 120),
              assetType,
              exchange: cleanText(item.exchDisp || item.exchange || 'NSE', 20),
              currency: String(item.symbol).endsWith('.NS') || String(item.symbol).endsWith('.BO') ? 'INR' : 'USD',
            })
          }
        })
        .catch(() => {}),
    )
  }
  if (wantMf) {
    tasks.push(
      fetch(`https://api.mfapi.in/mf/search?q=${encodeURIComponent(query)}`, {
        headers: { Accept: 'application/json' },
        signal: AbortSignal.timeout(5000),
      })
        .then((res) => (res.ok ? res.json() : null))
        .then((data) => {
          const rows = Array.isArray(data) ? data : []
          for (const row of rows.slice(0, 8)) {
            if (!row?.schemeCode || !row?.schemeName) continue
            results.push({
              symbol: `MF:${row.schemeCode}`,
              name: cleanText(row.schemeName, 140),
              assetType: 'mf',
              exchange: 'AMFI',
              currency: 'INR',
              schemeCode: String(row.schemeCode),
            })
          }
        })
        .catch(() => {}),
    )
  }

  await Promise.all(tasks)
  return json(response, 200, { ok: true, results: results.slice(0, 15) })
}

async function handleMarketQuotes(request, response, body, database) {
  const user = await authUser(request, database)
  const actorKey = user ? user.id : getClientIp(request)
  const limit = await checkRateLimit(`market-quotes:${actorKey}`, 60, 60 * 60 * 1000, database)
  if (!limit.ok) return json(response, 429, { error: `Too many quote refreshes. Wait ${limit.resetInSeconds}s.` })

  const instruments = Array.isArray(body.instruments) ? body.instruments.slice(0, 50) : []
  const now = Date.now()
  const quotes = {}

  await Promise.all(
    instruments.map(async (inst) => {
      const symbol = cleanText(inst?.symbol, 50)
      if (!symbol) return
      const cacheKey = `${symbol}|${cleanText(inst?.schemeCode, 20)}`
      const cached = marketQuoteCache.get(cacheKey)
      if (cached && now - cached.cachedAt < MARKET_CACHE_TTL_MS) {
        quotes[symbol] = { ...cached.quote, cached: true }
        return
      }
      let quote = null
      try {
        if (inst?.assetType === 'mf' && inst?.schemeCode) {
          quote = await fetchMfNav(inst.schemeCode)
        } else {
          const yahooSym = toYahooSymbol(symbol, inst?.exchange)
          if (yahooSym) quote = await fetchYahooQuote(yahooSym)
        }
      } catch {
        quote = null
      }
      if (quote) {
        const entry = { symbol, ...quote }
        marketQuoteCache.set(cacheKey, { quote: entry, cachedAt: now })
        quotes[symbol] = entry
      }
    }),
  )

  const fxRates = { INR: 1, USD: 84.5, EUR: 91.0 }
  try {
    const usdInr = await fetchYahooQuote('USDINR=X')
    if (usdInr?.priceMinor) fxRates.USD = Number((usdInr.priceMinor / 100).toFixed(4))
  } catch {}

  return json(response, 200, {
    ok: true,
    fetchedAt: new Date().toISOString(),
    fxRates,
    quotes,
  })
}

function normalizeReportAssetType(raw) {
  const v = String(raw || '').toLowerCase()
  if (v.includes('mutual') || v === 'mf') return 'mf'
  if (v.includes('gold')) return 'gold'
  if (v.includes('etf')) return 'etf'
  if (v.includes('bond') || v.includes('g-sec') || v.includes('fd') || v.includes('debenture')) return 'bond'
  return 'stock'
}

function parseCsvOrTextReport(text) {
  const lines = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
  const holdings = []
  const transactions = []
  for (const line of lines.slice(0, 300)) {
    const cols = line.split(',').map((c) => c.trim().replaceAll('"', ''))
    if (cols.length < 3) continue
    const first = cols[0].toLowerCase()
    if (first === 'symbol' || first === 'instrument' || first === 'name' || first === 'date') continue
    const qty = Number(cols[1])
    const price = Number(cols[2])
    if (Number.isFinite(qty) && qty > 0 && Number.isFinite(price) && price > 0) {
      const symbol = cleanText(cols[0], 50).toUpperCase()
      const assetType = normalizeReportAssetType(cols[3] || 'stock')
      const priceMinor = Math.round(price * 100)
      holdings.push({
        symbol,
        name: cleanText(cols[4] || symbol, 100),
        assetType,
        exchange: assetType === 'mf' ? 'AMFI' : 'NSE',
        currency: 'INR',
        quantity: qty,
        avgPriceMinor: priceMinor,
        currentPriceMinor: priceMinor,
      })
      transactions.push({
        symbol,
        assetType,
        action: 'buy',
        quantity: qty,
        priceMinor,
        currency: 'INR',
        occurredAt: new Date().toISOString(),
        source: 'report-import',
      })
    }
  }
  return { holdings, transactions }
}

async function handleImportInvestmentReport(request, response, body, database) {
  const user = await authUser(request, database)
  if (!user) return json(response, 401, { error: 'Sign in online to upload and scan investment reports.' })
  const limit = await checkRateLimit(`import-report:${user.id}`, 20, 60 * 60 * 1000, database)
  if (!limit.ok) return json(response, 429, { error: `Too many report imports. Wait ${limit.resetInSeconds}s.` })

  const mimeType = cleanText(body.mimeType, 64).toLowerCase()
  const reportType = cleanText(body.reportType, 24).toLowerCase() || 'cas'
  const base64Content = typeof body.base64Content === 'string' ? body.base64Content.trim() : ''
  const maxBytes = onVercel ? 3 * 1024 * 1024 : 10 * 1024 * 1024
  if (!ALLOWED_REPORT_MIME_TYPES.has(mimeType) || !base64Content) {
    return json(response, 400, { error: 'Upload a valid CAS/broker PDF, CSV, TXT, JSON, or image report.' })
  }
  const buffer = Buffer.from(base64Content, 'base64')
  if (!buffer.length || buffer.length > maxBytes) {
    return json(response, 400, { error: 'Report exceeds the allowed upload size limit.' })
  }
  if (ALLOWED_SCAN_MIME_TYPES.has(mimeType) && !matchesMagicBytes(buffer, mimeType)) {
    return json(response, 422, { ok: false, safe: false, error: 'File contents do not match its declared type.' })
  }
  if (hasUnsafeEmbeddedPayload(buffer, mimeType)) {
    return json(response, 422, { ok: false, safe: false, error: 'Report failed security scan (active script or launch action detected).' })
  }

  let holdings = []
  let transactions = []
  const warnings = []

  if (mimeType === 'text/csv' || mimeType === 'text/plain') {
    const parsed = parseCsvOrTextReport(buffer.toString('utf8'))
    holdings = parsed.holdings
    transactions = parsed.transactions
  } else if (mimeType === 'application/json') {
    try {
      const obj = JSON.parse(buffer.toString('utf8'))
      if (Array.isArray(obj?.holdings)) holdings = obj.holdings.slice(0, 200)
      if (Array.isArray(obj?.transactions)) transactions = obj.transactions.slice(0, 500)
    } catch {
      warnings.push('Could not parse JSON report structure.')
    }
  } else {
    const aiParsed = await callGeminiJson(
      'Extract investment holdings and buy/sell/SIP transactions from this CAS or broker statement. Return JSON {"holdings":[{"symbol":string,"name":string,"assetType":"stock"|"mf"|"etf"|"gold"|"bond","quantity":number,"avgPriceMinor":number,"currentPriceMinor":number}],"transactions":[{"symbol":string,"assetType":"stock"|"mf"|"etf"|"gold"|"bond","action":"buy"|"sell"|"sip"|"dividend","quantity":number,"priceMinor":number,"occurredAt":string}]}. Amounts in minor units (paise).',
      { mime_type: mimeType, data: base64Content },
    )
    if (aiParsed && (Array.isArray(aiParsed.holdings) || Array.isArray(aiParsed.transactions))) {
      holdings = Array.isArray(aiParsed.holdings) ? aiParsed.holdings.slice(0, 200) : []
      transactions = Array.isArray(aiParsed.transactions) ? aiParsed.transactions.slice(0, 500) : []
    } else {
      warnings.push('Document passed security scan. Configure GEMINI_API_KEY on backend for automatic PDF/image CAS extraction, or upload a CSV/JSON export.')
    }
  }

  const sha256 = createHash('sha256').update(buffer).digest('hex')
  return json(response, 200, {
    ok: true,
    safe: true,
    sha256,
    reportType,
    scannedAt: new Date().toISOString(),
    holdings,
    transactions,
    warnings,
  })
}

async function handleAiChat(request, response, body, database) {
  const user = await authUser(request, database)
  const actorKey = user ? user.id : getClientIp(request)
  const limit = await checkRateLimit(`ai-chat:${actorKey}`, 40, 60 * 60 * 1000, database)
  if (!limit.ok) return json(response, 429, { error: `Too many AI chat requests. Wait ${limit.resetInSeconds}s.` })

  const question = cleanText(body.question, 500)
  if (!question) return json(response, 400, { error: 'Enter a question for FinGrow AI.' })

  const summary = body.summary && typeof body.summary === 'object' ? body.summary : {}
  const history = Array.isArray(body.history) ? body.history.slice(-6) : []

  let reply = null
  let source = 'server-rules'
  const prompt = `You are FinGrow's personal finance assistant. Workspace totals (minor units): ${JSON.stringify(summary)}. Recent conversation: ${JSON.stringify(history)}. User question: "${question}". Return JSON {"reply": string} with a concise, practical answer.`
  const ollamaResult = await callOllamaJson(prompt)
  const aiResult = ollamaResult || (await callGeminiJson(prompt))
  if (typeof aiResult?.reply === 'string' && aiResult.reply.trim()) {
    reply = cleanText(aiResult.reply, 1200)
    source = ollamaResult ? 'ollama' : 'gemini'
  } else {
    const balance = Math.round(Number(summary.totalBalanceMinor || 0) / 100)
    const income = Math.round(Number(summary.monthlyIncomeMinor || 0) / 100)
    const expense = Math.round(Number(summary.monthlyExpenseMinor || 0) / 100)
    const overdue = Math.round(Number(summary.overdueMinor || 0) / 100)
    reply =
      overdue > 0
        ? `Based on your workspace (liquid balance ${balance}, income ${income}, expense ${expense}), prioritize clearing ${overdue} in overdue dues first, then allocate surplus toward your savings/investment goals.`
        : `Based on your workspace (liquid balance ${balance}, monthly income ${income}, expense ${expense}), your net monthly surplus is ${income - expense}. Connect an LLM key (GEMINI_API_KEY) on the backend later to enable full conversational AI answers.`
  }

  return json(response, 200, { ok: true, source, reply, answeredAt: new Date().toISOString() })
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
  if (request.method === 'POST' && pathname === '/v1/documents/scan') {
    return handleDocumentScan(request, response, await readJson(request), database)
  }
  if (request.method === 'POST' && pathname === '/v1/documents/analyze') {
    return handleDocumentAnalyze(request, response, await readJson(request), database)
  }
  if (request.method === 'POST' && pathname === '/v1/insights/ai') {
    return handleAiInsights(request, response, await readJson(request), database)
  }
  if (request.method === 'POST' && pathname === '/v1/insights/chat') {
    return handleAiChat(request, response, await readJson(request), database)
  }
  if (request.method === 'POST' && pathname === '/v1/mobile/sms/parse') {
    return handleMobileSmsParse(request, response, await readJson(request), database)
  }
  if (request.method === 'GET' && pathname === '/v1/market/search') {
    return handleMarketSearch(request, response, url, database)
  }
  if (request.method === 'POST' && pathname === '/v1/market/quotes') {
    return handleMarketQuotes(request, response, await readJson(request), database)
  }
  if (request.method === 'POST' && pathname === '/v1/investments/import-report') {
    return handleImportInvestmentReport(request, response, await readJson(request), database)
  }

  const profileRoute = /^\/v1\/profiles\/([A-Za-z0-9_-]{1,80})\/snapshot$/.exec(pathname)
  if (profileRoute && (request.method === 'GET' || request.method === 'PUT')) {
    const user = await authUser(request, database)
    if (!user) return json(response, 401, { error: 'Your sync session expired. Verify your email again to reconnect.' })
    if (!hasActiveCloudConsent(user)) {
      return json(response, 403, { error: 'Cloud sync consent is required or has been withdrawn.' })
    }
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
    const requestId = randomUUID()
    if (status >= 500) {
      console.error(`[FinGrow Backend ${requestId}]`, error?.message || 'Internal error')
    }
    const message =
      status >= 500 && !String(error.message || '').includes('TURSO_DATABASE_URL')
        ? 'The request could not be completed.'
        : error.message || 'The request could not be completed.'
    if (!response.headersSent) return json(response, status, status >= 500 ? { error: message, requestId } : { error: message })
    response.destroy()
  }
}

export default async function vercelHandler(request, response) {
  process.env.FINGROW_SERVERLESS = '1'
  return handleBackendRequest(request, response, { requireRemote: true })
}

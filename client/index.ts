export type SyncProfile = {
  id: string
  name: string
  kind: 'personal' | 'household' | 'business'
  currency: string
  syncSalt: string
  createdAt: string
}

export type BackendSession = {
  accessToken: string
  tokenExpiresInSeconds: number
  user: { id: string; email: string; fullName: string }
  profiles: SyncProfile[]
  activeProfileId: string
}

export type EncryptedSnapshotEnvelope = {
  formatVersion: 1
  iv: string
  ciphertext: string
}

export class FinGrowBackendError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message)
    this.name = 'FinGrowBackendError'
  }
}

export function backendBaseUrl(): string {
  const runtime = globalThis as typeof globalThis & {
    __FINGROW_BACKEND_URL__?: string
  }
  const configured = runtime.__FINGROW_BACKEND_URL__?.trim()
  if (configured) return secureBaseUrl(configured)
  if (typeof localStorage !== 'undefined') {
    const saved = localStorage.getItem('fingrow_backend_url')?.trim()
    if (saved) return secureBaseUrl(saved)
  }
  return 'http://127.0.0.1:4317'
}

function secureBaseUrl(value: string): string {
  const url = new URL(value)
  const localHost = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && localHost)) {
    throw new FinGrowBackendError(
      'Use HTTPS for the FinGrow server outside local development.',
      0,
    )
  }
  return value.replace(/\/+$/, '')
}

async function requestJson<T>(
  path: string,
  options: { method?: string; token?: string; body?: unknown } = {},
): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${backendBaseUrl()}${path}`, {
      method: options.method ?? 'GET',
      headers: {
        ...(options.body === undefined ? {} : { 'Content-Type': 'application/json' }),
        ...(options.token ? { Authorization: `Bearer ${options.token}` } : {}),
      },
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      cache: 'no-store',
    })
  } catch (error) {
    if (error instanceof FinGrowBackendError) throw error
    throw new FinGrowBackendError('FinGrow sync server could not be reached. Connect to the internet and try again.', 0)
  }
  const payload = (await response.json().catch(() => ({}))) as Record<string, unknown>
  if (!response.ok) {
    throw new FinGrowBackendError(
      typeof payload.error === 'string' ? payload.error : 'The sync server rejected the request.',
      response.status,
    )
  }
  return payload as T
}

export function requestEmailOtp(input: {
  email: string
  fullName: string
  currency?: string
}): Promise<{ challengeId: string; expiresInSeconds: number }> {
  return requestJson('/v1/auth/otp/request', {
    method: 'POST',
    body: { ...input, purpose: 'account' },
  })
}

export function verifyEmailOtp(input: {
  challengeId: string
  email: string
  fullName: string
  code: string
}): Promise<BackendSession> {
  return requestJson('/v1/auth/otp/verify', { method: 'POST', body: input })
}

export function requestProfileOtp(token: string, input: {
  email: string
  profileName: string
  profileKind: SyncProfile['kind']
  currency: string
}): Promise<{ challengeId: string; expiresInSeconds: number }> {
  return requestJson('/v1/auth/otp/request', {
    method: 'POST',
    token,
    body: { ...input, purpose: 'profile' },
  })
}

export function verifyProfileOtp(input: {
  token: string
  challengeId: string
  email: string
  code: string
}): Promise<BackendSession> {
  return requestJson('/v1/auth/otp/verify', {
    method: 'POST',
    token: input.token,
    body: {
      challengeId: input.challengeId,
      email: input.email,
      code: input.code,
    },
  })
}

export function readEncryptedSnapshot(
  token: string,
  profileId: string,
): Promise<{
  revision: number
  envelope: EncryptedSnapshotEnvelope | null
  updatedAt: string | null
}> {
  return requestJson(`/v1/profiles/${encodeURIComponent(profileId)}/snapshot`, { token })
}

export function writeEncryptedSnapshot(
  token: string,
  profileId: string,
  expectedRevision: number,
  envelope: EncryptedSnapshotEnvelope,
): Promise<{ revision: number; updatedAt: string }> {
  return requestJson(`/v1/profiles/${encodeURIComponent(profileId)}/snapshot`, {
    method: 'PUT',
    token,
    body: { expectedRevision, envelope },
  })
}

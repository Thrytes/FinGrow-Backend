import { handleBackendRequest } from '../src/server.mjs'

export const config = { api: { bodyParser: false } }

function resolvePath(req) {
  const candidate = req.headers['x-forwarded-uri'] || req.url || '/'
  const parsed = new URL(candidate, 'http://localhost')
  let p = parsed.pathname
  if (p === '/api/index' || p === '/api' || p === '' || p === '/index') {
    p = '/health'
  }
  return p + parsed.search
}

export default async function handler(req, res) {
  process.env.FINGROW_SERVERLESS = '1'
  req.url = resolvePath(req)
  return handleBackendRequest(req, res, { requireRemote: true })
}

import { handleBackendRequest } from '../src/server.mjs'

export const config = { api: { bodyParser: false } }

export default async function handler(req, res) {
  process.env.FINGROW_SERVERLESS = '1'
  const parsed = new URL(req.url || '/', 'http://localhost')
  const rewritten = req.query?.__path || parsed.searchParams.get('__path') || req.headers['x-forwarded-uri']
  if (rewritten) {
    req.url = rewritten
  } else if (parsed.pathname === '/api/index' || parsed.pathname === '/api') {
    req.url = '/health'
  }
  return handleBackendRequest(req, res, { requireRemote: true })
}

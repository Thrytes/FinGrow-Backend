import { handleBackendRequest } from '../src/server.mjs'

export const config = { api: { bodyParser: false } }

export default async function handler(req, res) {
  process.env.FINGROW_SERVERLESS = '1'
  const parsed = new URL(req.url || '/', 'http://localhost')
  const rewritten = parsed.searchParams.get('__path')
  if (rewritten) {
    parsed.searchParams.delete('__path')
    const search = parsed.searchParams.toString()
    req.url = rewritten + (search ? `?${search}` : '')
  } else if (parsed.pathname === '/api/index' || parsed.pathname === '/api') {
    req.url = '/health'
  }
  return handleBackendRequest(req, res, { requireRemote: true })
}

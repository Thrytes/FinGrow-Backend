import { handleBackendRequest } from '../src/server.mjs'

export const config = { api: { bodyParser: false } }

export default async function handler(req, res) {
  process.env.FINGROW_SERVERLESS = '1'
  let targetUrl = req.headers['x-matched-path'] || req.url || '/'
  if (targetUrl === '/' || targetUrl === '/api' || targetUrl === '/api/index') {
    targetUrl = '/health'
  } else if (targetUrl.startsWith('/api/')) {
    targetUrl = targetUrl.slice(4)
  }
  req.url = targetUrl
  return handleBackendRequest(req, res, { requireRemote: true })
}

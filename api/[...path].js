import { handleBackendRequest } from '../src/server.mjs'

export const config = { api: { bodyParser: false } }

export default async function handler(req, res) {
  process.env.FINGROW_SERVERLESS = '1'
  const candidate = req.headers['x-forwarded-uri'] || req.url || '/'
  const parsed = new URL(candidate, 'http://localhost')
  let p = parsed.pathname
  if (p.includes('[...path]') && req.query?.path) {
    const segments = Array.isArray(req.query.path) ? req.query.path.join('/') : req.query.path
    p = '/v1/' + segments
  }
  req.url = p + parsed.search
  return handleBackendRequest(req, res, { requireRemote: true })
}

process.env.FINGROW_SERVERLESS = '1'
import { handleBackendRequest } from '../src/server.mjs'

export const config = { api: { bodyParser: false } }

export default async function handler(req, res) {
  try {
    req.url = '/health'
    return await handleBackendRequest(req, res, { requireRemote: true })
  } catch (error) {
    if (!res.headersSent) {
      res.writeHead(500, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
      })
      res.end(JSON.stringify({ ok: false, error: error.message }))
    }
  }
}

import { handleBackendRequest } from '../src/server.mjs'

export const config = { api: { bodyParser: false } }

export default async function handler(req, res) {
  process.env.FINGROW_SERVERLESS = '1'
  req.url = '/health'
  return handleBackendRequest(req, res, { requireRemote: true })
}

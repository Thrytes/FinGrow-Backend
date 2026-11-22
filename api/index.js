export const config = { api: { bodyParser: false } }

export default async function handler(req, res) {
  try {
    process.env.FINGROW_SERVERLESS = '1'
    const { handleBackendRequest } = await import('../src/server.mjs')
    req.url = '/health'
    return await handleBackendRequest(req, res, { requireRemote: true })
  } catch (err) {
    if (!res.headersSent) {
      res.statusCode = 200
      res.setHeader('Content-Type', 'application/json; charset=utf-8')
      res.end(JSON.stringify({
        ok: false,
        source: 'index.js catch',
        error: err.message,
        stack: err.stack,
        node: process.version,
      }, null, 2))
    }
  }
}

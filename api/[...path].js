export const config = { api: { bodyParser: false } }

export default async function handler(req, res) {
  try {
    process.env.FINGROW_SERVERLESS = '1'
    const incomingUrl = req.url || '/'
    const url = new URL(incomingUrl, 'https://fingrow.invalid')
    if (url.pathname === '/api') url.pathname = '/'
    else if (url.pathname.startsWith('/api/')) url.pathname = url.pathname.slice(4)
    req.url = `${url.pathname}${url.search}`

    const { handleBackendRequest } = await import('../src/server.mjs')
    return await handleBackendRequest(req, res, { requireRemote: true })
  } catch (err) {
    if (!res.headersSent) {
      res.statusCode = 200
      res.setHeader('Content-Type', 'application/json; charset=utf-8')
      res.end(JSON.stringify({
        ok: false,
        source: '[...path].js catch',
        error: err.message,
        stack: err.stack,
        node: process.version,
      }, null, 2))
    }
  }
}

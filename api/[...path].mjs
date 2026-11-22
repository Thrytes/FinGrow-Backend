export const config = { api: { bodyParser: false } }

export default async function handler(request, response) {
  try {
    process.env.FINGROW_SERVERLESS = '1'
    const incomingUrl = request.url || '/'
    const url = new URL(incomingUrl, 'https://fingrow.invalid')
    if (url.pathname === '/api') url.pathname = '/'
    else if (url.pathname.startsWith('/api/')) url.pathname = url.pathname.slice(4)
    request.url = `${url.pathname}${url.search}`

    const { handleBackendRequest } = await import('../src/server.mjs')
    return await handleBackendRequest(request, response, { requireRemote: true })
  } catch (error) {
    if (!response.headersSent) {
      response.writeHead(500, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
      })
      response.end(JSON.stringify({
        ok: false,
        error: error.message || 'Serverless function encountered an initialization error.',
      }))
    }
  }
}

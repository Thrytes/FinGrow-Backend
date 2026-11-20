export const config = { api: { bodyParser: false } }

export default async function handler(request, response) {
  process.env.FINGROW_SERVERLESS = '1'
  const incomingUrl = request.url || '/'
  const url = new URL(incomingUrl, 'https://fingrow.invalid')
  if (url.pathname === '/api') url.pathname = '/'
  else if (url.pathname.startsWith('/api/')) url.pathname = url.pathname.slice(4)
  request.url = `${url.pathname}${url.search}`

  const { handleBackendRequest } = await import('../src/server.mjs')
  return handleBackendRequest(request, response, { requireRemote: true })
}

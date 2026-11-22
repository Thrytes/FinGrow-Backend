export const config = { api: { bodyParser: false } }

export default async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json; charset=utf-8')
  res.setHeader('Cache-Control', 'no-store')

  const envCheck = {
    hasOtpSecret: Boolean(process.env.FINGROW_OTP_HASH_SECRET),
    hasTokenSecret: Boolean(process.env.FINGROW_TOKEN_HASH_SECRET),
    hasTursoUrl: Boolean(process.env.TURSO_DATABASE_URL),
    hasTursoToken: Boolean(process.env.TURSO_AUTH_TOKEN),
    hasSmtpUser: Boolean(process.env.SMTP_USER),
  }

  let dbStatus = 'not configured'
  if (process.env.TURSO_DATABASE_URL && process.env.TURSO_AUTH_TOKEN) {
    try {
      const { createClient } = await import('@tursodatabase/serverless/compat')
      const client = createClient({
        url: process.env.TURSO_DATABASE_URL.trim(),
        authToken: process.env.TURSO_AUTH_TOKEN.trim(),
      })
      await client.execute('SELECT 1')
      client.close()
      dbStatus = 'connected'
    } catch (dbErr) {
      dbStatus = `connection error: ${dbErr.message}`
    }
  }

  res.statusCode = 200
  res.end(JSON.stringify({
    ok: true,
    service: 'fingrow-backend',
    storage: dbStatus,
    smtpConfigured: Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS),
    env: envCheck,
    node: process.version,
  }, null, 2))
}

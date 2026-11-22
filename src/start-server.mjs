import { createServer } from 'node:http'
import { handleBackendRequest, getStore } from './server.mjs'

const PORT = Number(process.env.FINGROW_BACKEND_PORT || 4317)
const HOST = process.env.FINGROW_BACKEND_HOST || '127.0.0.1'

const server = createServer((request, response) => {
  void handleBackendRequest(request, response)
})

getStore().then((database) => database.initialize()).then(() => {
  server.listen(PORT, HOST, () => {
    console.info(`FinGrow backend listening at http://${HOST}:${PORT}`)
  })
}).catch((error) => {
  console.error('FinGrow backend could not initialize storage:', error.message)
  process.exitCode = 1
})

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    server.close(async () => {
      try { (await getStore()).close() } catch {}
      process.exit(0)
    })
  })
}

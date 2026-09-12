import { createServer } from 'node:http'
import { DeploySealBroker } from './broker.js'

const port = Number(process.env.PORT || 8787)
const host = process.env.HOST || '127.0.0.1'
const broker = new DeploySealBroker()

function headers() {
  return {
    'access-control-allow-origin': process.env.CLIENT_ORIGIN || 'http://127.0.0.1:5173',
    'access-control-allow-methods': 'GET,POST,OPTIONS',
    'access-control-allow-headers': 'content-type',
    'cache-control': 'no-store',
    'content-type': 'application/json; charset=utf-8',
  }
}

function send(response, status, body) {
  response.writeHead(status, headers())
  response.end(JSON.stringify(body))
}

async function readJson(request) {
  const chunks = []
  let size = 0
  for await (const chunk of request) {
    size += chunk.length
    if (size > 1024 * 1024) throw Object.assign(new Error('request too large'), { statusCode: 413 })
    chunks.push(chunk)
  }
  if (!chunks.length) return {}
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'))
  } catch {
    throw Object.assign(new Error('invalid JSON'), { statusCode: 400 })
  }
}

function validScenario(value) {
  return ['crash', 'happy', 'invalid'].includes(value) ? value : 'crash'
}

const server = createServer(async (request, response) => {
  if (request.method === 'OPTIONS') {
    response.writeHead(204, headers())
    response.end()
    return
  }

  const url = new URL(request.url || '/', `http://${request.headers.host || 'localhost'}`)

  try {
    if (request.method === 'GET' && url.pathname === '/api/health') {
      send(response, 200, { ok: true, mode: 'local-emulator' })
      return
    }

    if (request.method === 'GET' && url.pathname === '/api/release') {
      send(response, 200, broker.snapshot())
      return
    }

    if (request.method === 'POST' && url.pathname === '/api/release/start') {
      const body = await readJson(request)
      const result = await broker.start({ scenario: validScenario(body?.scenario) })
      send(response, result.accepted || result.code === 'OPERATION_EXISTS' ? 200 : 422, result)
      return
    }

    if (request.method === 'POST' && url.pathname === '/api/release/recover') {
      const result = await broker.recover()
      send(response, result.accepted ? 200 : 409, result)
      return
    }

    if (request.method === 'POST' && url.pathname === '/api/release/replay') {
      const result = await broker.replay()
      send(response, 409, result)
      return
    }

    if (request.method === 'POST' && url.pathname === '/api/audit/disclose') {
      const body = await readJson(request)
      const fields = Array.isArray(body?.fields) ? body.fields.slice(0, 8) : []
      const result = await broker.disclose(fields)
      send(response, result.accepted ? 200 : 409, result)
      return
    }

    if (request.method === 'POST' && url.pathname === '/api/receipt/verify') {
      send(response, 200, await broker.verifyReceipt())
      return
    }

    if (request.method === 'POST' && url.pathname === '/api/reset') {
      send(response, 200, { accepted: true, snapshot: await broker.reset() })
      return
    }

    send(response, 404, { error: { code: 'NOT_FOUND', message: 'Not found' } })
  } catch (error) {
    const status = Number.isInteger(error.statusCode) ? error.statusCode : 500
    send(response, status, { error: { code: 'INTERNAL_ERROR', message: status === 500 ? 'Request failed' : error.message } })
  }
})

if (process.argv[1] === new URL(import.meta.url).pathname) {
  server.listen(port, host, () => {
    console.log(`DeploySeal local broker listening on http://${host}:${port}`)
  })
}

export { server, broker }

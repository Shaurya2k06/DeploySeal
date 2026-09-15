const DEFAULT_BACKEND = 'https://deployseal-cvm-260912.eastus.cloudapp.azure.com'

function sendJson(response, status, body) {
  response.statusCode = status
  response.setHeader('cache-control', 'no-store')
  response.setHeader('content-type', 'application/json; charset=utf-8')
  response.end(JSON.stringify(body))
}

module.exports = async function handler(request, response) {
  const token = process.env.DEPLOYSEAL_API_TOKEN
  if (!token) {
    sendJson(response, 503, { error: { code: 'GATEWAY_CONFIG', message: 'DeploySeal gateway is not configured' } })
    return
  }

  let backend
  try {
    backend = new URL(process.env.DEPLOYSEAL_BACKEND_URL || DEFAULT_BACKEND)
  } catch {
    sendJson(response, 500, { error: { code: 'GATEWAY_CONFIG', message: 'DeploySeal backend URL is invalid' } })
    return
  }
  if (backend.protocol !== 'https:') {
    sendJson(response, 500, { error: { code: 'GATEWAY_CONFIG', message: 'DeploySeal backend must use HTTPS' } })
    return
  }

  try {
    const incoming = new URL(request.url || '/', 'https://deployseal.local')
    const path = incoming.pathname.replace(/^\/api\/?/u, '')
    const target = new URL(`/api/${path}`, backend)
    target.search = incoming.search
    const hasBody = !['GET', 'HEAD'].includes(request.method)
    let body
    if (hasBody && request.body !== undefined) {
      body = typeof request.body === 'string' || Buffer.isBuffer(request.body)
        ? request.body
        : JSON.stringify(request.body)
    }
    const upstream = await fetch(target, {
      method: request.method,
      headers: {
        accept: 'application/json',
        authorization: `Bearer ${token}`,
        ...(request.headers['content-type'] ? { 'content-type': request.headers['content-type'] } : {}),
      },
      ...(body === undefined ? {} : { body }),
    })
    const responseBody = await upstream.text()
    response.statusCode = upstream.status
    response.setHeader('cache-control', 'no-store')
    response.setHeader('content-type', upstream.headers.get('content-type') || 'application/json; charset=utf-8')
    response.end(responseBody)
  } catch {
    sendJson(response, 502, { error: { code: 'GATEWAY_UNAVAILABLE', message: 'DeploySeal backend is unavailable' } })
  }
}

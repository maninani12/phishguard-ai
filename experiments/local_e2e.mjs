// Local end-to-end harness for the PhishGuard AI demo.
//
// Simulates exactly what the browser does, using the same fetch() semantics:
//   1. load the Vite dev server document and its transformed module graph
//   2. verify the frontend module actually calls the agent endpoint
//   3. issue the identical requests agentClient.js issues, with a browser Origin
//      header so CORS is genuinely exercised
//   4. validate the response contract and the safety guarantees
//
// SAFETY: this harness only ever contacts 127.0.0.1:5173 (the dev server) and
// 127.0.0.1:8013 (the PhishGuard API). Every other URL is submitted as a JSON
// string and is never requested. The contacted-host list is asserted at the end.

const DEV = 'http://127.0.0.1:5173'
const API = 'http://127.0.0.1:8013'
const ORIGIN = 'http://127.0.0.1:5173'

const contacted = new Set()
let pass = 0
let fail = 0

function ok(label) { pass++; console.log(`  PASS  ${label}`) }
function bad(label, detail) { fail++; console.log(`  FAIL  ${label}${detail ? ' :: ' + detail : ''}`) }

async function check(label, fn) {
  try { const r = await fn(); if (r === false) bad(label, 'returned false'); else ok(label) } catch (e) { bad(label, e.message) }
}

async function devGet(path) {
  contacted.add(new URL(path, DEV).origin)
  const res = await fetch(`${DEV}${path}`)
  return { status: res.status, text: await res.text() }
}

async function apiGet(path) {
  contacted.add(new URL(path, API).origin)
  const res = await fetch(`${API}${path}`, { headers: { Origin: ORIGIN } })
  return { status: res.status, body: await res.json(), cors: res.headers.get('access-control-allow-origin') }
}

async function apiPost(path, url) {
  contacted.add(new URL(path, API).origin)
  const res = await fetch(`${API}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: ORIGIN },
    body: JSON.stringify({ url }),
  })
  let body = null
  try { body = await res.json() } catch { /* non-JSON error body */ }
  return { status: res.status, body }
}

const REQUIRED = ['url', 'prediction', 'label', 'confidence', 'risk_level', 'signals',
  'explanation', 'recommendation', 'disclaimer']

function validateContract(body) {
  for (const key of REQUIRED) if (!(key in body)) throw new Error(`missing field: ${key}`)
  if (body.label !== 0 && body.label !== 1) throw new Error('label not in {0,1}')
  if (typeof body.confidence !== 'number' || body.confidence < 0 || body.confidence > 1) throw new Error('bad confidence')
  if (!Array.isArray(body.signals) || !Array.isArray(body.explanation)) throw new Error('signals/explanation not arrays')
  if (!body.explanation.length) throw new Error('explanation empty')
  if (typeof body.recommendation !== 'string' || !body.recommendation) throw new Error('no recommendation')
  if (body.website_visited !== false) throw new Error('website_visited is not false')
  if (!/apex/i.test(body.research_notice || '')) throw new Error('research notice missing the apex limitation')
}

async function main() {
  console.log('\n== 1. Vite dev server ==')
  await check('dev server serves the app document', async () => {
    const { status, text } = await devGet('/')
    if (status !== 200) throw new Error(`status ${status}`)
    if (!text.includes('id="root"')) throw new Error('no #root mount point')
    if (!text.includes('/src/main.jsx')) throw new Error('main.jsx not referenced')
  })
  await check('dev server transforms main.jsx', async () => {
    const { status, text } = await devGet('/src/main.jsx')
    if (status !== 200) throw new Error(`status ${status}`)
    if (!text.includes('createRoot')) throw new Error('main.jsx not transformed as expected')
  })
  await check('dev server transforms api.js with the loopback guard', async () => {
    const { status, text } = await devGet('/src/api.js')
    if (status !== 200) throw new Error(`status ${status}`)
    if (!text.includes('LOOPBACK')) throw new Error('loopback guard missing from dev transform')
  })
  await check('dev server transforms agentClient.js calling the agent endpoint', async () => {
    const { status, text } = await devGet('/src/agentClient.js')
    if (status !== 200) throw new Error(`status ${status}`)
    if (!text.includes('/api/agent/analyze')) throw new Error('agent endpoint not present in dev transform')
    if (!text.includes('/api/predict')) throw new Error('predict endpoint not present in dev transform')
  })
  await check('frontend module graph contains no submitted-URL fetching', async () => {
    const { text } = await devGet('/src/agentClient.js')
    for (const bad of ['XMLHttpRequest', 'axios', 'sendBeacon', 'new WebSocket', 'window.open']) {
      if (text.includes(bad)) throw new Error(`agentClient references ${bad}`)
    }
  })

  console.log('\n== 2. Existing API surface (regression) ==')
  await check('GET /', async () => {
    const { status, body } = await apiGet('/')
    if (status !== 200 || body.status !== 'ready') throw new Error(`status ${status}`)
  })
  await check('GET /api/health', async () => {
    const { status, body, cors } = await apiGet('/api/health')
    if (status !== 200 || body.model_loaded !== true) throw new Error(`status ${status}`)
    if (cors !== ORIGIN) throw new Error(`CORS not permitting dev origin (got ${cors})`)
  })
  await check('GET /api/model_info', async () => {
    const { status, body } = await apiGet('/api/model_info')
    if (status !== 200) throw new Error(`status ${status}`)
    if (body.features !== 38) throw new Error(`expected 38 features, got ${body.features}`)
    if (body.model !== 'Decision Tree') throw new Error(`unexpected model ${body.model}`)
  })
  await check('POST /api/predict unchanged', async () => {
    const { status, body } = await apiPost('/api/predict', 'https://www.example.com/')
    if (status !== 200) throw new Error(`status ${status}`)
    for (const k of ['normalized_url', 'label', 'confidence', 'features', 'analysis']) {
      if (!(k in body)) throw new Error(`missing ${k}`)
    }
    if (Object.keys(body.features).length !== 38) throw new Error('feature count changed')
  })

  console.log('\n== 3. Agent endpoint: valid URLs ==')
  const cases = [
    ['https://www.example.com/', 'legitimate www root'],
    ['https://example.com/', 'legitimate apex (known blind spot)'],
    ['http://192.0.2.5:8080/login?next=%2Fadmin', 'IP + port + keyword + query + encoding'],
    ['https://www.iana.org/help/example-domains', 'legitimate with a path'],
    ['https://bit.ly/3xam-ple', 'known shortener'],
    ['https://xn--nxasmq6b.example.com/', 'punycode host'],
    ['http://www.example.com/', 'plain HTTP'],
  ]
  for (const [url, note] of cases) {
    await check(`agent: ${note}`, async () => {
      const { status, body } = await apiPost('/api/agent/analyze', url)
      if (status !== 200) throw new Error(`status ${status}`)
      validateContract(body)
      console.log(`          -> ${body.prediction} | score ${(body.confidence * 100).toFixed(1)}% | ` +
        `risk ${body.risk_level} | signals ${body.signals.length} | gaps ${body.training_distribution_gaps.length}`)
      return true
    })
  }

  console.log('\n== 4. Agent endpoint: invalid input (must surface as errors) ==')
  const bad = [
    ['', 'empty'],
    ['   ', 'whitespace only'],
    ['not a url', 'malformed'],
    ['ftp://example.com/x', 'ftp scheme'],
    ['javascript:alert(1)', 'script scheme'],
    ['http://', 'no host'],
    ['https://example.com/' + 'a'.repeat(3000), 'over 2048 chars'],
    ['https://example.com/\nmalicious', 'control character'],
  ]
  for (const [url, note] of bad) {
    await check(`agent rejects: ${note}`, async () => {
      const { status, body } = await apiPost('/api/agent/analyze', url)
      if (status !== 422) throw new Error(`expected 422, got ${status}`)
      if (!body.detail) throw new Error('no error detail returned for the UI to display')
      return true
    })
  }

  console.log('\n== 5. Agent and predict agree ==')
  for (const url of ['https://www.example.com/', 'https://example.com/', 'http://192.0.2.5:8080/login?next=%2Fadmin']) {
    await check(`agreement: ${url.slice(0, 44)}`, async () => {
      const a = (await apiPost('/api/agent/analyze', url)).body
      const p = (await apiPost('/api/predict', url)).body
      if (a.label !== p.label) throw new Error(`label ${a.label} vs ${p.label}`)
      if (a.normalized_url !== p.normalized_url) throw new Error('normalized URL differs')
      return true
    })
  }

  console.log('\n== 6. Safety guarantees ==')
  await check('no explanatory claim about the website itself', async () => {
    const banned = ['i visited', 'we visited', 'we scanned', 'we opened', 'we fetched',
      'contains malware', 'definitely malicious', 'confirmed malicious',
      '100% safe', '100% protection', 'website is safe']
    for (const url of ['https://www.example.com/', 'https://example.com/', 'http://192.0.2.5:8080/login']) {
      const { body } = await apiPost('/api/agent/analyze', url)
      const text = [...body.explanation, body.recommendation].join(' ').toLowerCase()
      for (const phrase of banned) if (text.includes(phrase)) throw new Error(`"${phrase}" in output`)
    }
  })
  await check('known limitation is disclosed for an apex URL', async () => {
    const { body } = await apiPost('/api/agent/analyze', 'https://example.com/')
    if (!body.training_distribution_gaps.length) throw new Error('no distribution gap reported')
    if (!/apex/i.test(body.training_distribution_gaps.join(' '))) throw new Error('apex gap not named')
  })
  await check('harness contacted only the local dev server and API', () => {
    const allowed = new Set([DEV, API])
    for (const host of contacted) if (!allowed.has(host)) throw new Error(`unexpected host contacted: ${host}`)
    console.log(`          contacted only: ${[...contacted].join(', ')}`)
    return true
  })

  console.log(`\n== RESULT: ${pass} passed, ${fail} failed ==`)
  process.exit(fail === 0 ? 0 : 1)
}

main().catch((e) => { console.error('HARNESS ERROR', e); process.exit(2) })

// Client for the PhishGuard API.
//
// SAFETY: the only network destination is the configured PhishGuard API base URL.
// The submitted URL is sent as a JSON string to that API and is never requested,
// opened, or navigated to by the browser.
import { API_BASE_URL, API_CONFIGURED, API_NOT_CONFIGURED_MESSAGE } from './api.js'

function detailToMessage(body, fallback) {
  const detail = body?.detail
  if (Array.isArray(detail)) return detail.map((item) => item.msg).join(' • ')
  if (typeof detail === 'string') return detail
  return fallback
}

async function postJson(path, payload) {
  if (!API_CONFIGURED) throw new Error(API_NOT_CONFIGURED_MESSAGE)
  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  let body = null
  try {
    body = await response.json()
  } catch {
    body = null
  }
  if (!response.ok) {
    throw new Error(detailToMessage(body, 'The PhishGuard API could not analyze that URL.') || 'Request failed.')
  }
  return body
}

export async function getHealth() {
  if (!API_CONFIGURED) throw new Error(API_NOT_CONFIGURED_MESSAGE)
  const response = await fetch(`${API_BASE_URL}/api/health`)
  if (!response.ok) throw new Error('API unavailable')
  return response.json()
}

export async function getModelInfo() {
  if (!API_CONFIGURED) throw new Error(API_NOT_CONFIGURED_MESSAGE)
  const response = await fetch(`${API_BASE_URL}/api/model_info`)
  if (!response.ok) throw new Error('API unavailable')
  return response.json()
}

/** Run the PhishGuard agent: prediction + evidence-based explanation + guidance. */
export function analyzeUrl(url) {
  return postJson('/api/agent/analyze', { url: url.trim() })
}

/** Raw model prediction, kept for the feature-inspection panel. */
export function predictUrl(url) {
  return postJson('/api/predict', { url: url.trim() })
}

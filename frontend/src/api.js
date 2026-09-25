// Client configuration for the PhishGuard API.
//
// SAFETY: the only network destination the browser is allowed to contact is the
// configured PhishGuard API base URL. A submitted URL is sent to that API as a
// JSON string and is never requested, opened, or navigated to.
//
// The production build must never point at localhost. If VITE_API_BASE_URL is
// missing, or is a loopback address in a production build, the API is treated as
// not configured and the UI shows a clear "API not connected" message instead of
// silently calling a developer's own machine.
const configuredBaseUrl = import.meta.env.VITE_API_BASE_URL?.trim()
const localDevelopmentUrl = import.meta.env.DEV ? 'http://127.0.0.1:8013' : ''
const isDev = Boolean(import.meta.env.DEV)

const LOOPBACK = /^https?:\/\/(127\.0\.0\.1|localhost|\[::1\])(:\d+)?(\/|$)/i

function resolveBase() {
  const configured = configuredBaseUrl || localDevelopmentUrl
  if (!configured) return ''
  // A loopback base is only meaningful for local development.
  if (LOOPBACK.test(configured) && !isDev) return ''
  return configured.replace(/\/+$/, '')
}

export const API_BASE_URL = resolveBase()
export const API_CONFIGURED = Boolean(API_BASE_URL)
export const API_NOT_CONFIGURED_MESSAGE = 'PhishGuard API is not connected. The backend deployment is required for live URL analysis.'

export function apiFetch(path, options) {
  if (!API_CONFIGURED) {
    return Promise.reject(new Error(API_NOT_CONFIGURED_MESSAGE))
  }
  return fetch(`${API_BASE_URL}${path}`, options)
}

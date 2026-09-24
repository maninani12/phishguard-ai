const configuredBaseUrl = import.meta.env.VITE_API_BASE_URL?.trim()
const localDevelopmentUrl = import.meta.env.DEV ? 'http://127.0.0.1:8010' : ''

export const API_BASE_URL = (configuredBaseUrl || localDevelopmentUrl).replace(/\/+$/, '')
export const API_CONFIGURED = Boolean(API_BASE_URL)
export const API_NOT_CONFIGURED_MESSAGE = 'PhishGuard API is not connected. The backend deployment is required for live URL analysis.'

export function apiFetch(path, options) {
  if (!API_CONFIGURED) {
    return Promise.reject(new Error(API_NOT_CONFIGURED_MESSAGE))
  }
  return fetch(`${API_BASE_URL}${path}`, options)
}

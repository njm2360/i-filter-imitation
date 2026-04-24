export function encodeSegment(s: string): string {
  return encodeURIComponent(s)
}

export async function apiFetch(path: string, options: RequestInit = {}): Promise<Response> {
  const apiKey = localStorage.getItem('apiKey') ?? ''
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  }
  if (apiKey) {
    headers['Authorization'] = `Bearer ${apiKey}`
  }

  const res = await fetch(path, { ...options, headers })

  if (res.status === 401) {
    window.dispatchEvent(new CustomEvent('auth:unauthorized'))
  }

  return res
}

import { apiFetch, encodeSegment } from './client'
import type { ScanSetting, MimeTypeEntry } from '../types'

export async function getScanSettings(): Promise<ScanSetting[]> {
  const res = await apiFetch('/api/v1/scan/settings')
  if (!res.ok) throw new Error(await errorMessage(res))
  return res.json()
}

export async function updateScanSetting(key: string, value: string, actor: string): Promise<void> {
  const res = await apiFetch('/api/v1/scan/settings', {
    method: 'PATCH',
    body: JSON.stringify({ key, value, actor }),
  })
  if (!res.ok) throw new Error(await errorMessage(res))
}

export async function listMimeTypes(params: {
  enabled?: string
  q?: string
  sort?: string
  order?: string
}): Promise<MimeTypeEntry[]> {
  const qs = new URLSearchParams()
  if (params.enabled) qs.set('enabled', params.enabled)
  if (params.q) qs.set('q', params.q)
  if (params.sort) qs.set('sort', params.sort)
  if (params.order) qs.set('order', params.order)
  const res = await apiFetch(`/api/v1/scan/mime-types?${qs}`)
  if (!res.ok) throw new Error(await errorMessage(res))
  return res.json()
}

export async function updateMimeType(
  pattern: string,
  patch: { enabled?: boolean; note?: string; actor: string },
): Promise<MimeTypeEntry> {
  const res = await apiFetch(`/api/v1/scan/mime-types/${encodeSegment(pattern)}`, {
    method: 'PATCH',
    body: JSON.stringify(patch),
  })
  if (!res.ok) throw new Error(await errorMessage(res))
  return res.json()
}

async function errorMessage(res: Response): Promise<string> {
  try {
    const body = await res.json()
    return body.error ?? `HTTP ${res.status}`
  } catch {
    return `HTTP ${res.status}`
  }
}

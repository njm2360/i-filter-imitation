import { apiFetch, encodeSegment } from './client'
import type { Entry, AuditEntry, PagedResponse } from '../types'

export async function listBlocklist(params: {
  enabled?: string
  q?: string
  sort?: string
  order?: string
  page?: number
  limit?: number
}): Promise<PagedResponse<Entry>> {
  const qs = new URLSearchParams()
  if (params.enabled) qs.set('enabled', params.enabled)
  if (params.q) qs.set('q', params.q)
  if (params.sort) qs.set('sort', params.sort)
  if (params.order) qs.set('order', params.order)
  if (params.page) qs.set('page', String(params.page))
  if (params.limit) qs.set('limit', String(params.limit))
  const res = await apiFetch(`/api/v1/blocklist?${qs}`)
  if (!res.ok) throw new Error(await errorMessage(res))
  return res.json()
}

export async function addBlocklistEntry(domain: string, comment: string, actor: string): Promise<Entry> {
  const res = await apiFetch('/api/v1/blocklist', {
    method: 'POST',
    body: JSON.stringify({ domain, comment, actor }),
  })
  if (!res.ok) throw new Error(await errorMessage(res))
  return res.json()
}

export async function updateBlocklistEntry(
  domain: string,
  patch: { enabled?: boolean; comment?: string; actor: string },
): Promise<Entry> {
  const res = await apiFetch(`/api/v1/blocklist/${encodeSegment(domain)}`, {
    method: 'PATCH',
    body: JSON.stringify(patch),
  })
  if (!res.ok) throw new Error(await errorMessage(res))
  return res.json()
}

export async function deleteBlocklistEntry(domain: string, actor: string, comment?: string): Promise<void> {
  const res = await apiFetch(`/api/v1/blocklist/${encodeSegment(domain)}`, {
    method: 'DELETE',
    body: JSON.stringify({ actor, comment: comment ?? '' }),
  })
  if (!res.ok) throw new Error(await errorMessage(res))
}

export async function getAuditLog(
  domain: string,
  params: { page?: number; limit?: number } = {},
): Promise<PagedResponse<AuditEntry>> {
  const qs = new URLSearchParams()
  if (params.page) qs.set('page', String(params.page))
  if (params.limit) qs.set('limit', String(params.limit))
  const res = await apiFetch(`/api/v1/blocklist/${encodeSegment(domain)}/audit?${qs}`)
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

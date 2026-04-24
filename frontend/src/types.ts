export interface PagedResponse<T> {
  total: number
  page: number
  limit: number
  items: T[]
}

export interface Entry {
  id: number
  domain: string
  enabled: boolean
  comment: string
  created_by: string
  created_at: string
  updated_by: string
  updated_at: string
}

export interface AuditEntry {
  id: number
  domain: string
  action: 'add' | 'update' | 'enable' | 'disable' | 'remove'
  actor: string
  comment: string
  occurred_at: string
}

export interface ScanSetting {
  key: string
  value: string
  updated_by: string
  updated_at: string
}

export interface MimeTypeEntry {
  id: number
  pattern: string
  is_prefix: boolean
  enabled: boolean
  note: string
  updated_by: string
  updated_at: string
}

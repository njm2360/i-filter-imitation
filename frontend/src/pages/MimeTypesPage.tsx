import { useEffect, useState } from 'react'
import { listMimeTypes, updateMimeType } from '../api/scan'
import { useAuth } from '../context/AuthContext'
import { useToast } from '../components/Toast'
import { StatusBadge } from '../components/StatusBadge'
import type { MimeTypeEntry } from '../types'

const formatDate = (iso: string) =>
  new Intl.DateTimeFormat('ja-JP', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit',
  }).format(new Date(iso))

export function MimeTypesPage() {
  const { actorName } = useAuth()
  const { showToast } = useToast()

  const [entries, setEntries] = useState<MimeTypeEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [query, setQuery] = useState('')
  const [filterEnabled, setFilterEnabled] = useState('')

  const [editingId, setEditingId] = useState<number | null>(null)
  const [editNote, setEditNote] = useState('')
  const [editLoading, setEditLoading] = useState(false)

  useEffect(() => {
    const timer = setTimeout(() => {
      setLoading(true)
      listMimeTypes({ q: query, enabled: filterEnabled })
        .then(setEntries)
        .catch(e => showToast(String(e), 'danger'))
        .finally(() => setLoading(false))
    }, query ? 300 : 0)
    return () => clearTimeout(timer)
  }, [query, filterEnabled])

  const handleToggleEnabled = async (entry: MimeTypeEntry) => {
    try {
      const updated = await updateMimeType(entry.pattern, {
        enabled: !entry.enabled,
        actor: actorName,
      })
      setEntries(prev => prev.map(e => (e.id === updated.id ? updated : e)))
      showToast(updated.enabled ? '有効にしました' : '無効にしました')
    } catch (e) {
      showToast(String(e), 'danger')
    }
  }

  const startEdit = (entry: MimeTypeEntry) => {
    setEditingId(entry.id)
    setEditNote(entry.note)
  }

  const cancelEdit = () => {
    setEditingId(null)
    setEditNote('')
  }

  const handleSaveNote = async (entry: MimeTypeEntry) => {
    setEditLoading(true)
    try {
      const updated = await updateMimeType(entry.pattern, {
        note: editNote,
        actor: actorName,
      })
      setEntries(prev => prev.map(e => (e.id === updated.id ? updated : e)))
      setEditingId(null)
      showToast('メモを更新しました')
    } catch (e) {
      showToast(String(e), 'danger')
    } finally {
      setEditLoading(false)
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <h5 className="mb-3 fw-bold">MIME タイプ</h5>

      <div className="d-flex gap-2 mb-2 align-items-center">
        <input
          type="search"
          className="form-control form-control-sm"
          placeholder="パターンで絞り込み"
          value={query}
          onChange={e => setQuery(e.target.value)}
          style={{ maxWidth: 240 }}
        />
        <select
          className="form-select form-select-sm"
          value={filterEnabled}
          onChange={e => setFilterEnabled(e.target.value)}
          style={{ maxWidth: 140 }}
        >
          <option value="">全件</option>
          <option value="true">有効のみ</option>
        </select>
        <span className="text-muted small">{entries.length} 件</span>
      </div>

      <div className="table-responsive" style={{ flex: 1, overflowY: 'auto' }}>
        <table className="table table-hover table-sm align-middle">
          <thead className="table-light" style={{ position: 'sticky', top: 0, zIndex: 1 }}>
            <tr>
              <th>パターン</th>
              <th>種別</th>
              <th>状態</th>
              <th>メモ</th>
              <th className="text-nowrap">更新日時</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={6} className="text-center py-4 text-muted">読み込み中…</td>
              </tr>
            ) : entries.length === 0 ? (
              <tr>
                <td colSpan={6} className="text-center py-4 text-muted">エントリがありません</td>
              </tr>
            ) : (
              entries.map(entry => (
                <tr key={entry.id}>
                  <td>
                    <span className="font-monospace small">{entry.pattern}</span>
                  </td>
                  <td>
                    {entry.is_prefix ? (
                      <span className="badge bg-warning text-dark">前方一致</span>
                    ) : (
                      <span className="badge bg-light text-dark border">完全一致</span>
                    )}
                  </td>
                  <td>
                    <StatusBadge enabled={entry.enabled} />
                  </td>
                  <td style={{ minWidth: 180 }}>
                    {editingId === entry.id ? (
                      <div className="d-flex gap-1">
                        <input
                          type="text"
                          className="form-control form-control-sm"
                          value={editNote}
                          onChange={e => setEditNote(e.target.value)}
                          style={{ minWidth: 160 }}
                        />
                        <button
                          className="btn btn-sm btn-primary"
                          onClick={() => handleSaveNote(entry)}
                          disabled={editLoading}
                        >
                          {editLoading ? '…' : '保存'}
                        </button>
                        <button
                          className="btn btn-sm btn-secondary"
                          onClick={cancelEdit}
                          disabled={editLoading}
                        >
                          ×
                        </button>
                      </div>
                    ) : (
                      <span className="text-truncate d-inline-block" style={{ maxWidth: 200 }} title={entry.note}>
                        {entry.note || <span className="text-muted">—</span>}
                      </span>
                    )}
                  </td>
                  <td className="text-nowrap small text-muted">{formatDate(entry.updated_at)}</td>
                  <td className="text-nowrap">
                    <button
                      className={`btn btn-sm me-1 ${entry.enabled ? 'btn-outline-secondary' : 'btn-outline-success'}`}
                      onClick={() => handleToggleEnabled(entry)}
                    >
                      {entry.enabled ? '無効化' : '有効化'}
                    </button>
                    {editingId !== entry.id && (
                      <button
                        className="btn btn-sm btn-outline-primary"
                        onClick={() => startEdit(entry)}
                      >
                        メモ編集
                      </button>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

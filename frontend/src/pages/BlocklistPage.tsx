import { useEffect, useRef, useState } from 'react'
import * as bootstrap from 'bootstrap'
import {
  listBlocklist,
  addBlocklistEntry,
  updateBlocklistEntry,
  deleteBlocklistEntry,
  getAuditLog,
} from '../api/blocklist'
import { useAuth } from '../context/AuthContext'
import { useToast } from '../components/Toast'
import { StatusBadge } from '../components/StatusBadge'
import type { Entry, AuditEntry } from '../types'

type SortKey = 'domain' | 'created_at' | 'updated_at'

const formatDate = (iso: string) =>
  new Intl.DateTimeFormat('ja-JP', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit',
  }).format(new Date(iso))

const auditBadge = (action: AuditEntry['action']) => {
  const map: Record<AuditEntry['action'], string> = {
    add: 'bg-primary',
    update: 'bg-info text-dark',
    enable: 'bg-success',
    disable: 'bg-secondary',
    remove: 'bg-danger',
  }
  return <span className={`badge ${map[action]}`}>{action}</span>
}

export function BlocklistPage() {
  const { actorName } = useAuth()
  const { showToast } = useToast()

  const [entries, setEntries] = useState<Entry[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const limit = 100
  const [loading, setLoading] = useState(true)
  const [query, setQuery] = useState('')
  const [filterEnabled, setFilterEnabled] = useState('')
  const [sort, setSort] = useState<SortKey>('created_at')
  const [order, setOrder] = useState<'asc' | 'desc'>('desc')

  const [addDomain, setAddDomain] = useState('')
  const [addComment, setAddComment] = useState('')
  const [addLoading, setAddLoading] = useState(false)

  const [editEntry, setEditEntry] = useState<Entry | null>(null)
  const [editComment, setEditComment] = useState('')
  const [editLoading, setEditLoading] = useState(false)

  const [deleteEntry, setDeleteEntry] = useState<Entry | null>(null)
  const [deleteReason, setDeleteReason] = useState('')
  const [deleteLoading, setDeleteLoading] = useState(false)

  const [auditEntry, setAuditEntry] = useState<Entry | null>(null)
  const [auditLog, setAuditLog] = useState<AuditEntry[]>([])
  const [auditTotal, setAuditTotal] = useState(0)
  const [auditPage, setAuditPage] = useState(1)
  const auditLimit = 50
  const [auditLoading, setAuditLoading] = useState(false)

  const editModalRef = useRef<HTMLDivElement>(null)
  const deleteModalRef = useRef<HTMLDivElement>(null)
  const auditModalRef = useRef<HTMLDivElement>(null)

  const editModal = useRef<bootstrap.Modal | null>(null)
  const deleteModal = useRef<bootstrap.Modal | null>(null)
  const auditModal = useRef<bootstrap.Modal | null>(null)

  useEffect(() => {
    if (editModalRef.current) editModal.current = new bootstrap.Modal(editModalRef.current)
    if (deleteModalRef.current) deleteModal.current = new bootstrap.Modal(deleteModalRef.current)
    if (auditModalRef.current) auditModal.current = new bootstrap.Modal(auditModalRef.current)
  }, [])

  useEffect(() => {
    setPage(1)
  }, [query, filterEnabled, sort, order])

  useEffect(() => {
    const timer = setTimeout(() => {
      setLoading(true)
      listBlocklist({ q: query, enabled: filterEnabled, sort, order, page, limit })
        .then(res => { setEntries(res.items); setTotal(res.total) })
        .catch(e => showToast(String(e), 'danger'))
        .finally(() => setLoading(false))
    }, query ? 300 : 0)
    return () => clearTimeout(timer)
  }, [query, filterEnabled, sort, order, page])

  const toggleSort = (key: SortKey) => {
    if (sort === key) {
      setOrder(o => (o === 'asc' ? 'desc' : 'asc'))
    } else {
      setSort(key)
      setOrder('desc')
    }
  }

  const sortIndicator = (key: SortKey) => {
    if (sort !== key) return <span className="text-muted ms-1">↕</span>
    return <span className="ms-1">{order === 'asc' ? '▲' : '▼'}</span>
  }

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!addDomain.trim()) return
    setAddLoading(true)
    try {
      const entry = await addBlocklistEntry(addDomain.trim(), addComment, actorName)
      setEntries(prev => [entry, ...prev])
      setAddDomain('')
      setAddComment('')
      showToast('登録しました')
    } catch (e: unknown) {
      const msg = String(e)
      if (msg.includes('409') || msg.toLowerCase().includes('exist')) {
        showToast('既に登録済みのドメインです', 'danger')
      } else {
        showToast(msg, 'danger')
      }
    } finally {
      setAddLoading(false)
    }
  }

  const handleToggleEnabled = async (entry: Entry) => {
    try {
      const updated = await updateBlocklistEntry(entry.domain, {
        enabled: !entry.enabled,
        actor: actorName,
      })
      setEntries(prev => prev.map(e => (e.id === updated.id ? updated : e)))
      showToast(updated.enabled ? '有効にしました' : '無効にしました')
    } catch (e) {
      showToast(String(e), 'danger')
    }
  }

  const openEdit = (entry: Entry) => {
    setEditEntry(entry)
    setEditComment(entry.comment)
    editModal.current?.show()
  }

  const handleEditSave = async () => {
    if (!editEntry) return
    setEditLoading(true)
    try {
      const updated = await updateBlocklistEntry(editEntry.domain, {
        comment: editComment,
        actor: actorName,
      })
      setEntries(prev => prev.map(e => (e.id === updated.id ? updated : e)))
      editModal.current?.hide()
      showToast('コメントを更新しました')
    } catch (e) {
      showToast(String(e), 'danger')
    } finally {
      setEditLoading(false)
    }
  }

  const openDelete = (entry: Entry) => {
    setDeleteEntry(entry)
    setDeleteReason('')
    deleteModal.current?.show()
  }

  const handleDelete = async () => {
    if (!deleteEntry) return
    setDeleteLoading(true)
    try {
      await deleteBlocklistEntry(deleteEntry.domain, actorName, deleteReason)
      setEntries(prev => prev.filter(e => e.id !== deleteEntry.id))
      deleteModal.current?.hide()
      showToast('削除しました')
    } catch (e) {
      showToast(String(e), 'danger')
    } finally {
      setDeleteLoading(false)
    }
  }

  const fetchAuditPage = async (entry: Entry, p: number) => {
    setAuditLoading(true)
    try {
      const res = await getAuditLog(entry.domain, { page: p, limit: auditLimit })
      setAuditLog(res.items)
      setAuditTotal(res.total)
      setAuditPage(p)
    } catch (e) {
      showToast(String(e), 'danger')
    } finally {
      setAuditLoading(false)
    }
  }

  const openAudit = (entry: Entry) => {
    setAuditEntry(entry)
    setAuditLog([])
    setAuditTotal(0)
    setAuditPage(1)
    auditModal.current?.show()
    fetchAuditPage(entry, 1)
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <h5 className="mb-3 fw-bold">ブロックリスト</h5>

      {/* 追加フォーム */}
      <form onSubmit={handleAdd} className="mb-3">
        <div className="input-group">
          <input
            type="text"
            className="form-control"
            placeholder="ドメイン（例: *.example.com）"
            value={addDomain}
            onChange={e => setAddDomain(e.target.value)}
            style={{ maxWidth: 280 }}
            required
          />
          <input
            type="text"
            className="form-control"
            placeholder="コメント（任意）"
            value={addComment}
            onChange={e => setAddComment(e.target.value)}
            style={{ maxWidth: 300 }}
          />
          <button type="submit" className="btn btn-primary" disabled={addLoading}>
            {addLoading ? '登録中…' : '追加'}
          </button>
        </div>
      </form>

      {/* フィルター */}
      <div className="d-flex gap-2 mb-2 align-items-center">
        <input
          type="search"
          className="form-control form-control-sm"
          placeholder="ドメイン / コメントで絞り込み"
          value={query}
          onChange={e => setQuery(e.target.value)}
          style={{ maxWidth: 260 }}
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
        <span className="text-muted small">{total} 件</span>
      </div>

      {/* テーブル */}
      <div className="table-responsive" style={{ flex: 1, overflowY: 'auto' }}>
        <table className="table table-hover table-sm align-middle">
          <thead className="table-light" style={{ position: 'sticky', top: 0, zIndex: 1 }}>
            <tr>
              <th style={{ cursor: 'pointer' }} onClick={() => toggleSort('domain')}>
                ドメイン{sortIndicator('domain')}
              </th>
              <th>状態</th>
              <th>コメント</th>
              <th style={{ cursor: 'pointer', whiteSpace: 'nowrap' }} onClick={() => toggleSort('created_at')}>
                登録日時{sortIndicator('created_at')}
              </th>
              <th style={{ cursor: 'pointer', whiteSpace: 'nowrap' }} onClick={() => toggleSort('updated_at')}>
                更新日時{sortIndicator('updated_at')}
              </th>
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
                    <span className="font-monospace">
                      {entry.domain.startsWith('*.') && (
                        <span className="text-muted">*.</span>
                      )}
                      {entry.domain.startsWith('*.') ? entry.domain.slice(2) : entry.domain}
                    </span>
                  </td>
                  <td>
                    <StatusBadge enabled={entry.enabled} />
                  </td>
                  <td>
                    <span
                      className="d-inline-block text-truncate"
                      style={{ maxWidth: 200 }}
                      title={entry.comment}
                    >
                      {entry.comment || <span className="text-muted">—</span>}
                    </span>
                  </td>
                  <td className="text-nowrap small text-muted">{formatDate(entry.created_at)}</td>
                  <td className="text-nowrap small text-muted">{formatDate(entry.updated_at)}</td>
                  <td className="text-nowrap">
                    <button
                      className={`btn btn-sm me-1 ${entry.enabled ? 'btn-outline-secondary' : 'btn-outline-success'}`}
                      onClick={() => handleToggleEnabled(entry)}
                      title={entry.enabled ? '無効にする' : '有効にする'}
                    >
                      {entry.enabled ? '無効化' : '有効化'}
                    </button>
                    <button
                      className="btn btn-sm btn-outline-primary me-1"
                      onClick={() => openEdit(entry)}
                      title="コメント編集"
                    >
                      編集
                    </button>
                    <button
                      className="btn btn-sm btn-outline-secondary me-1"
                      onClick={() => openAudit(entry)}
                      title="変更履歴"
                    >
                      履歴
                    </button>
                    <button
                      className="btn btn-sm btn-outline-danger"
                      onClick={() => openDelete(entry)}
                      title="削除"
                    >
                      削除
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* ページネーション */}
      {total > limit && (
        <div className="d-flex align-items-center gap-2 pt-2 border-top">
          <nav>
            <ul className="pagination pagination-sm mb-0">
              <li className={`page-item ${page === 1 ? 'disabled' : ''}`}>
                <button className="page-link" onClick={() => setPage(p => p - 1)}>‹</button>
              </li>
              {Array.from({ length: Math.ceil(total / limit) }, (_, i) => i + 1)
                .filter(p => p === 1 || p === Math.ceil(total / limit) || Math.abs(p - page) <= 2)
                .reduce<(number | '…')[]>((acc, p, i, arr) => {
                  if (i > 0 && p - (arr[i - 1] as number) > 1) acc.push('…')
                  acc.push(p)
                  return acc
                }, [])
                .map((p, i) =>
                  p === '…' ? (
                    <li key={`ellipsis-${i}`} className="page-item disabled">
                      <span className="page-link">…</span>
                    </li>
                  ) : (
                    <li key={p} className={`page-item ${page === p ? 'active' : ''}`}>
                      <button className="page-link" onClick={() => setPage(p as number)}>{p}</button>
                    </li>
                  )
                )}
              <li className={`page-item ${page === Math.ceil(total / limit) ? 'disabled' : ''}`}>
                <button className="page-link" onClick={() => setPage(p => p + 1)}>›</button>
              </li>
            </ul>
          </nav>
          <span className="text-muted small">
            {(page - 1) * limit + 1}–{Math.min(page * limit, total)} / {total} 件
          </span>
        </div>
      )}

      {/* コメント編集モーダル */}
      <div ref={editModalRef} className="modal fade" tabIndex={-1}>
        <div className="modal-dialog">
          <div className="modal-content">
            <div className="modal-header">
              <h5 className="modal-title">コメント編集</h5>
              <button type="button" className="btn-close" data-bs-dismiss="modal" />
            </div>
            <div className="modal-body">
              {editEntry && (
                <div className="mb-1 font-monospace text-muted small">{editEntry.domain}</div>
              )}
              <textarea
                className="form-control"
                rows={3}
                value={editComment}
                onChange={e => setEditComment(e.target.value)}
              />
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" data-bs-dismiss="modal">キャンセル</button>
              <button className="btn btn-primary" onClick={handleEditSave} disabled={editLoading}>
                {editLoading ? '保存中…' : '保存'}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* 削除確認モーダル */}
      <div ref={deleteModalRef} className="modal fade" tabIndex={-1}>
        <div className="modal-dialog">
          <div className="modal-content">
            <div className="modal-header">
              <h5 className="modal-title">削除の確認</h5>
              <button type="button" className="btn-close" data-bs-dismiss="modal" />
            </div>
            <div className="modal-body">
              <p>
                <span className="font-monospace fw-bold">{deleteEntry?.domain}</span> を削除しますか？
              </p>
              <p className="text-muted small">この操作は取り消せません。監査ログは保持されます。</p>
              <div className="mb-0">
                <label className="form-label small">理由（任意）</label>
                <input
                  type="text"
                  className="form-control form-control-sm"
                  value={deleteReason}
                  onChange={e => setDeleteReason(e.target.value)}
                  placeholder="削除理由"
                />
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" data-bs-dismiss="modal">キャンセル</button>
              <button className="btn btn-danger" onClick={handleDelete} disabled={deleteLoading}>
                {deleteLoading ? '削除中…' : '削除する'}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* 監査ログモーダル */}
      <div ref={auditModalRef} className="modal fade" tabIndex={-1}>
        <div className="modal-dialog modal-lg">
          <div className="modal-content">
            <div className="modal-header">
              <h5 className="modal-title">
                変更履歴
                {auditEntry && (
                  <span className="font-monospace fw-normal text-muted ms-2 fs-6">
                    {auditEntry.domain}
                  </span>
                )}
              </h5>
              <button type="button" className="btn-close" data-bs-dismiss="modal" />
            </div>
            <div className="modal-body p-0">
              {auditLoading ? (
                <div className="text-center py-4 text-muted">読み込み中…</div>
              ) : (
                <table className="table table-sm mb-0">
                  <thead className="table-light">
                    <tr>
                      <th>操作</th>
                      <th>操作者</th>
                      <th>コメント</th>
                      <th className="text-nowrap">日時</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditLog.length === 0 ? (
                      <tr>
                        <td colSpan={4} className="text-center py-3 text-muted">履歴がありません</td>
                      </tr>
                    ) : (
                      auditLog.map(log => (
                        <tr key={log.id}>
                          <td>{auditBadge(log.action)}</td>
                          <td>{log.actor || <span className="text-muted">—</span>}</td>
                          <td>{log.comment || <span className="text-muted">—</span>}</td>
                          <td className="text-nowrap small text-muted">{formatDate(log.occurred_at)}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              )}
            </div>
            <div className="modal-footer d-flex align-items-center justify-content-between">
              <div className="d-flex align-items-center gap-2">
                {auditTotal > auditLimit && (
                  <>
                    <button
                      className="btn btn-sm btn-outline-secondary"
                      disabled={auditPage === 1 || auditLoading}
                      onClick={() => auditEntry && fetchAuditPage(auditEntry, auditPage - 1)}
                    >
                      ‹ 前
                    </button>
                    <span className="text-muted small">
                      {auditPage} / {Math.ceil(auditTotal / auditLimit)} ページ（全 {auditTotal} 件）
                    </span>
                    <button
                      className="btn btn-sm btn-outline-secondary"
                      disabled={auditPage >= Math.ceil(auditTotal / auditLimit) || auditLoading}
                      onClick={() => auditEntry && fetchAuditPage(auditEntry, auditPage + 1)}
                    >
                      次 ›
                    </button>
                  </>
                )}
                {auditTotal <= auditLimit && auditTotal > 0 && (
                  <span className="text-muted small">全 {auditTotal} 件</span>
                )}
              </div>
              <button className="btn btn-secondary" data-bs-dismiss="modal">閉じる</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

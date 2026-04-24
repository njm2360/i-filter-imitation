import { useEffect, useState } from 'react'
import { getScanSettings, updateScanSetting } from '../api/scan'
import { useAuth } from '../context/AuthContext'
import { useToast } from '../components/Toast'
import type { ScanSetting } from '../types'

const formatDate = (iso: string) =>
  new Intl.DateTimeFormat('ja-JP', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit',
  }).format(new Date(iso))

export function ScanSettingsPage() {
  const { actorName } = useAuth()
  const { showToast } = useToast()

  const [settings, setSettings] = useState<ScanSetting[]>([])
  const [loading, setLoading] = useState(true)
  const [savingKey, setSavingKey] = useState<string | null>(null)
  const [maxSizeDraft, setMaxSizeDraft] = useState('')

  useEffect(() => {
    getScanSettings()
      .then(data => {
        setSettings(data)
        const maxSize = data.find(s => s.key === 'max_size_mb')
        if (maxSize) setMaxSizeDraft(maxSize.value)
      })
      .catch(e => showToast(String(e), 'danger'))
      .finally(() => setLoading(false))
  }, [])

  const handleToggleEnabled = async (current: ScanSetting) => {
    const newVal = current.value === 'true' ? 'false' : 'true'
    setSavingKey('enabled')
    try {
      await updateScanSetting('enabled', newVal, actorName)
      setSettings(prev =>
        prev.map(s => s.key === 'enabled' ? { ...s, value: newVal, updated_by: actorName, updated_at: new Date().toISOString() } : s)
      )
      showToast(newVal === 'true' ? 'スキャンを有効にしました' : 'スキャンを無効にしました')
    } catch (e) {
      showToast(String(e), 'danger')
    } finally {
      setSavingKey(null)
    }
  }

  const handleSaveMaxSize = async () => {
    const val = parseInt(maxSizeDraft)
    if (!maxSizeDraft || isNaN(val) || val < 1) {
      showToast('1 以上の整数を入力してください', 'warning')
      return
    }
    setSavingKey('max_size_mb')
    try {
      await updateScanSetting('max_size_mb', String(val), actorName)
      setSettings(prev =>
        prev.map(s => s.key === 'max_size_mb' ? { ...s, value: String(val), updated_by: actorName, updated_at: new Date().toISOString() } : s)
      )
      showToast('最大ファイルサイズを更新しました')
    } catch (e) {
      showToast(String(e), 'danger')
    } finally {
      setSavingKey(null)
    }
  }

  if (loading) return <div className="text-muted">読み込み中…</div>

  const enabledSetting = settings.find(s => s.key === 'enabled')
  const maxSizeSetting = settings.find(s => s.key === 'max_size_mb')

  return (
    <div style={{ maxWidth: 560 }}>
      <h5 className="mb-3 fw-bold">スキャン設定</h5>

      {/* スキャン有効/無効 */}
      {enabledSetting && (
        <div className="card mb-3">
          <div className="card-body">
            <div className="d-flex align-items-center justify-content-between mb-2">
              <div>
                <div className="fw-semibold">スキャン機能</div>
                <div className="text-muted small">HTTP レスポンスのウイルススキャンを有効にします</div>
              </div>
              <div className="form-check form-switch mb-0">
                <input
                  className="form-check-input"
                  type="checkbox"
                  role="switch"
                  id="scanEnabled"
                  checked={enabledSetting.value === 'true'}
                  onChange={() => handleToggleEnabled(enabledSetting)}
                  disabled={savingKey === 'enabled'}
                  style={{ width: '3em', height: '1.5em' }}
                />
              </div>
            </div>
            <div className="text-muted small">
              最終更新: {formatDate(enabledSetting.updated_at)}
            </div>
          </div>
        </div>
      )}

      {/* 最大ファイルサイズ */}
      {maxSizeSetting && (
        <div className="card mb-3">
          <div className="card-body">
            <div className="fw-semibold mb-1">最大スキャンサイズ</div>
            <div className="text-muted small mb-2">この値を超えるレスポンスはスキャンをスキップします</div>
            <div className="input-group" style={{ maxWidth: 220 }}>
              <input
                type="number"
                className="form-control"
                min={1}
                value={maxSizeDraft}
                onChange={e => setMaxSizeDraft(e.target.value)}
              />
              <span className="input-group-text">MB</span>
              <button
                className="btn btn-primary"
                onClick={handleSaveMaxSize}
                disabled={savingKey === 'max_size_mb'}
              >
                {savingKey === 'max_size_mb' ? '保存中…' : '保存'}
              </button>
            </div>
            <div className="text-muted small mt-2">
              最終更新: {formatDate(maxSizeSetting.updated_at)}
            </div>
          </div>
        </div>
      )}

      {/* その他の設定キー（将来拡張用） */}
      {settings
        .filter(s => s.key !== 'enabled' && s.key !== 'max_size_mb')
        .map(s => (
          <div key={s.key} className="card mb-3">
            <div className="card-body">
              <div className="fw-semibold mb-1 font-monospace">{s.key}</div>
              <input type="text" className="form-control" value={s.value} disabled />
              <div className="text-muted small mt-1">
                最終更新: {formatDate(s.updated_at)}
              </div>
            </div>
          </div>
        ))}
    </div>
  )
}

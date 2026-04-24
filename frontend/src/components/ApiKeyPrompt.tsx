import { useEffect, useRef, useState } from 'react'
import * as bootstrap from 'bootstrap'
import { useAuth } from '../context/AuthContext'

export function ApiKeyPrompt() {
  const { showPrompt, setApiKey, setActorName, setShowPrompt } = useAuth()
  const [key, setKey] = useState('')
  const [actor, setActor] = useState('')
  const [isUnauthorized, setIsUnauthorized] = useState(false)
  const modalRef = useRef<HTMLDivElement>(null)
  const modalInstance = useRef<bootstrap.Modal | null>(null)

  useEffect(() => {
    if (modalRef.current) {
      modalInstance.current = new bootstrap.Modal(modalRef.current, {
        backdrop: 'static',
        keyboard: false,
      })
    }
  }, [])

  useEffect(() => {
    if (!modalInstance.current) return
    if (showPrompt) {
      modalInstance.current.show()
    } else {
      modalInstance.current.hide()
    }
  }, [showPrompt])

  useEffect(() => {
    const handler = () => setIsUnauthorized(true)
    window.addEventListener('auth:unauthorized', handler)
    return () => window.removeEventListener('auth:unauthorized', handler)
  }, [])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!key.trim() || !actor.trim()) return
    setApiKey(key.trim())
    setActorName(actor.trim())
    setIsUnauthorized(false)
    setShowPrompt(false)
  }

  return (
    <div ref={modalRef} className="modal fade" tabIndex={-1}>
      <div className="modal-dialog modal-dialog-centered">
        <div className="modal-content">
          <div className="modal-header">
            <h5 className="modal-title">API キー設定</h5>
          </div>
          <form onSubmit={handleSubmit}>
            <div className="modal-body">
              {isUnauthorized && (
                <div className="alert alert-danger py-2">
                  API キーが無効または期限切れです。再入力してください。
                </div>
              )}
              <div className="mb-3">
                <label className="form-label">API キー</label>
                <input
                  type="password"
                  className="form-control"
                  value={key}
                  onChange={e => setKey(e.target.value)}
                  placeholder="Bearer トークンを入力"
                  required
                />
              </div>
              <div className="mb-3">
                <label className="form-label">作業者名（actor）</label>
                <input
                  type="text"
                  className="form-control"
                  value={actor}
                  onChange={e => setActor(e.target.value)}
                  placeholder="例: admin"
                  required
                />
                <div className="form-text">変更操作の記録に使われます。</div>
              </div>
            </div>
            <div className="modal-footer">
              <button type="submit" className="btn btn-primary">保存して続ける</button>
            </div>
          </form>
        </div>
      </div>
    </div>
  )
}

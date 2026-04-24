import { NavLink } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

export function Sidebar() {
  const { actorName, setShowPrompt } = useAuth()

  const linkClass = ({ isActive }: { isActive: boolean }) =>
    `nav-link px-3 py-2 rounded ${isActive ? 'active bg-primary text-white' : 'text-dark'}`

  return (
    <div className="d-flex flex-column bg-light border-end" style={{ width: 220, height: '100vh', position: 'sticky', top: 0, flexShrink: 0 }}>
      <div className="px-3 py-3 border-bottom">
        <span className="fw-bold text-primary fs-6">i-Filter 管理</span>
      </div>
      <nav className="nav flex-column p-2 flex-grow-1">
        <NavLink to="/" end className={linkClass}>
          ブロックリスト
        </NavLink>
        <NavLink to="/scan/settings" className={linkClass}>
          スキャン設定
        </NavLink>
        <NavLink to="/scan/mime-types" className={linkClass}>
          MIME タイプ
        </NavLink>
      </nav>
      <div className="px-3 py-2 border-top">
        <div className="text-muted small">作業者</div>
        <div className="fw-semibold text-truncate" style={{ maxWidth: 180 }}>
          {actorName || '—'}
        </div>
        <button
          className="btn btn-link btn-sm p-0 text-secondary"
          onClick={() => setShowPrompt(true)}
        >
          変更
        </button>
      </div>
    </div>
  )
}

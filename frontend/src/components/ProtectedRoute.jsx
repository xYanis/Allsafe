import { useState } from 'react'
import { Navigate } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext.jsx'
import { changePassword } from '../api/client.js'
import { canAccessPage } from '../utils/pageAccess.js'
import PasswordInput from './PasswordInput.jsx'
import PasswordStrengthHint, { passwordMeetsPolicy } from './PasswordStrengthHint.jsx'

// Écran bloquant affiché tant que must_change_password est vrai (compte bootstrap ou
// reset forcé par un admin, cf. backend/routers/users.py) — avant de rendre quoi que
// ce soit d'autre de l'app.
function ForcedPasswordChange() {
  const { refresh, logout } = useAuth()
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    if (submitting) return
    setSubmitting(true)
    setError('')
    try {
      await changePassword(current, next)
      await refresh()
    } catch (err) {
      setError(err?.response?.data?.detail || 'Impossible de changer le mot de passe.')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-6" style={{ background: 'var(--bg-app)' }}>
      <form onSubmit={handleSubmit} className="w-full max-w-sm rounded-2xl p-6 space-y-3"
        style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }}>
        <div>
          <h2 className="font-semibold" style={{ color: 'var(--text-primary)' }}>Changement de mot de passe requis</h2>
          <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
            Choisissez un nouveau mot de passe respectant les critères ci-dessous avant de continuer.
          </p>
        </div>
        <div>
          <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Mot de passe actuel</label>
          <PasswordInput autoFocus value={current} onChange={e => setCurrent(e.target.value)} />
        </div>
        <div>
          <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Nouveau mot de passe</label>
          <PasswordInput minLength={16} value={next} onChange={e => setNext(e.target.value)} />
          {next && <PasswordStrengthHint password={next} />}
        </div>
        {error && <p className="text-xs" style={{ color: '#f85149' }}>{error}</p>}
        <div className="flex gap-2 pt-1">
          <button type="button" onClick={logout}
            className="text-xs px-3 py-2 rounded-lg font-medium"
            style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}
          >Se déconnecter</button>
          <button type="submit" disabled={submitting || !passwordMeetsPolicy(next)}
            className="flex-1 text-sm px-3 py-2 rounded-lg font-medium disabled:opacity-50"
            style={{ background: 'color-mix(in srgb, var(--brand) 15%, transparent)', color: 'var(--brand)', border: '1px solid color-mix(in srgb, var(--brand) 35%, transparent)' }}
          >{submitting ? 'Enregistrement…' : 'Valider'}</button>
        </div>
      </form>
    </div>
  )
}

export default function ProtectedRoute({ children, role, page }) {
  const { user, loading } = useAuth()

  if (loading) return null
  if (!user) return <Navigate to="/login" replace />
  if (user.must_change_password) return <ForcedPasswordChange />
  if (role && user.role !== role) return <Navigate to="/" replace />
  if (page && !canAccessPage(user, page)) return <Navigate to="/" replace />

  return children
}

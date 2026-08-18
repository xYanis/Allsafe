import { useState } from 'react'
import PasswordInput from './PasswordInput.jsx'
import PasswordStrengthHint, { passwordMeetsPolicy } from './PasswordStrengthHint.jsx'

const MODULE_COLOR = '#fb8f44'

// Traitement d'une demande « mot de passe oublié » (18/08/2026, cf. Login.jsx et
// backend/routers/users.py::resolve_password_reset_request) — l'admin fixe lui-même le
// mot de passe provisoire, comme à la création d'un compte (UserFormModal.jsx), plutôt
// qu'un lien envoyé par email : aucune infra SMTP dans ce projet on-prem. Le mot de passe
// saisi ici doit être communiqué à l'utilisateur hors application (oral, chat interne...).
export default function ResolvePasswordResetModal({ request, onConfirm, onClose }) {
  const [password, setPassword] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  async function confirm() {
    if (saving || !passwordMeetsPolicy(password)) return
    setSaving(true)
    setError('')
    try {
      await onConfirm(password)
    } catch (e) {
      setError(e?.response?.data?.detail || "Impossible d'enregistrer ce mot de passe.")
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 modal-backdrop animate-backdrop-in" onClick={onClose}>
      <div className="max-w-md w-full rounded-2xl flex flex-col animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
          <h2 className="font-semibold" style={{ color: MODULE_COLOR }}>Fixer un mot de passe provisoire</h2>
          <button onClick={onClose} className="p-1.5 rounded-lg" style={{ color: 'var(--text-muted)' }}>
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>
        <div className="p-6 space-y-3">
          <div>
            <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{request.full_name}</p>
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{request.email}</p>
          </div>
          {request.message && (
            <div className="rounded-lg p-2.5 text-xs" style={{ background: 'var(--bg-secondary)', color: 'var(--text-secondary)' }}>
              « {request.message} »
            </div>
          )}
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Mot de passe provisoire</label>
            <PasswordInput autoFocus value={password} onChange={e => setPassword(e.target.value)} />
            {password && <PasswordStrengthHint password={password} />}
            <p className="text-xs mt-1" style={{ color: 'var(--text-faint)' }}>
              À communiquer à l'utilisateur hors de l'application. Changement forcé à sa prochaine connexion.
            </p>
          </div>
          {error && <p className="text-xs" style={{ color: '#f85149' }}>{error}</p>}
          <div className="flex justify-end gap-2 pt-1">
            <button onClick={onClose}
              className="text-xs px-3 py-2 rounded-lg font-medium"
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}
            >Annuler</button>
            <button onClick={confirm} disabled={!passwordMeetsPolicy(password) || saving}
              className="text-xs px-3 py-2 rounded-lg font-medium disabled:opacity-50"
              style={{ background: `${MODULE_COLOR}26`, color: MODULE_COLOR, border: `1px solid ${MODULE_COLOR}59` }}
            >{saving ? 'Enregistrement…' : 'Valider'}</button>
          </div>
        </div>
      </div>
    </div>
  )
}

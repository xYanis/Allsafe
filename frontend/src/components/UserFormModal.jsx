import { useState } from 'react'
import PasswordInput from './PasswordInput.jsx'
import { MODULE_PAGE_TREE } from '../constants/modulePages.js'

const MODULE_COLOR = '#fb8f44'
const MIN_PASSWORD_LENGTH = 16

// Création/édition d'un compte utilisateur (cf. backend/routers/users.py, réservé admin).
// Email modifiable en édition (avec contrôle d'unicité côté serveur) — c'est le rôle
// d'un admin de corriger une adresse mal saisie sans devoir supprimer/recréer le compte.
// Mot de passe saisissable uniquement à la création — ensuite, soit l'utilisateur le
// change lui-même (cf. routers/auth.py::change_password), soit un admin force un reset
// via "forcer le changement" ci-dessous.
export default function UserFormModal({ initial, onConfirm, onClose }) {
  const isEdit = Boolean(initial?.id)
  const [email, setEmail] = useState(initial?.email || '')
  const [fullName, setFullName] = useState(initial?.full_name || '')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState(initial?.role || 'analyst')
  const [isActive, setIsActive] = useState(initial?.is_active ?? true)
  const [forceReset, setForceReset] = useState(false)
  // Droits d'accès par module/page (31/07/2026, cf. models.py::User.allowed_pages) — seul un
  // compte analyst est concerné (admin voit toujours tout). `fullAccess` reflète
  // `allowed_pages === null/undefined` (accès total, défaut à la création) ; sinon la sélection
  // détaillée. `initial` peut être `null` (création) : le défaut "tout accessible" tombe alors
  // naturellement puisque `initial?.allowed_pages` vaut `undefined`.
  const [fullAccess, setFullAccess] = useState(initial?.allowed_pages == null)
  const [selectedPages, setSelectedPages] = useState(() => new Set(initial?.allowed_pages || []))
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  function togglePage(to) {
    setSelectedPages(prev => {
      const next = new Set(prev)
      if (next.has(to)) next.delete(to)
      else next.add(to)
      return next
    })
  }
  function toggleModule(pages, allSelected) {
    setSelectedPages(prev => {
      const next = new Set(prev)
      pages.forEach(p => allSelected ? next.delete(p.to) : next.add(p.to))
      return next
    })
  }

  async function confirm() {
    if (saving) return
    if (!fullName.trim() || !email.trim() || (!isEdit && password.length < MIN_PASSWORD_LENGTH)) return
    setSaving(true)
    setError('')
    try {
      const accessPayload = role !== 'analyst' ? {}
        : isEdit
          ? (fullAccess ? { grant_full_access: true } : { allowed_pages: [...selectedPages] })
          : { allowed_pages: fullAccess ? null : [...selectedPages] }
      if (isEdit) {
        await onConfirm({ email: email.trim(), full_name: fullName.trim(), role, is_active: isActive, force_password_reset: forceReset, ...accessPayload })
      } else {
        await onConfirm({ email: email.trim(), full_name: fullName.trim(), password, role, ...accessPayload })
      }
    } catch (e) {
      setError(e?.response?.data?.detail || "Impossible d'enregistrer ce compte.")
    } finally {
      setSaving(false)
    }
  }

  const canSubmit = fullName.trim() && email.trim() && (isEdit || password.length >= MIN_PASSWORD_LENGTH)

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 modal-backdrop animate-backdrop-in" onClick={onClose}>
      <div className="max-w-md w-full rounded-2xl flex flex-col animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
          <h2 className="font-semibold" style={{ color: MODULE_COLOR }}>{isEdit ? 'Modifier le compte' : 'Ajouter un compte'}</h2>
          <button onClick={onClose} className="p-1.5 rounded-lg" style={{ color: 'var(--text-muted)' }}>
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>
        <div className="p-6 space-y-3">
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Email</label>
            <input autoFocus type="email" value={email} onChange={e => setEmail(e.target.value)}
              className="w-full text-sm rounded-lg px-3 py-2 outline-none"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }} />
          </div>
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Nom</label>
            <input value={fullName} onChange={e => setFullName(e.target.value)} placeholder="Ex : Prénom Nom"
              className="w-full text-sm rounded-lg px-3 py-2 outline-none"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }} />
          </div>
          {!isEdit && (
            <div>
              <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Mot de passe provisoire</label>
              <PasswordInput minLength={MIN_PASSWORD_LENGTH} value={password} onChange={e => setPassword(e.target.value)} />
              <p className="text-xs mt-1" style={{ color: 'var(--text-faint)' }}>{MIN_PASSWORD_LENGTH} caractères minimum. Changement forcé à la première connexion.</p>
            </div>
          )}
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Rôle</label>
            <div className="flex gap-1.5">
              {[['analyst', 'Analyste'], ['admin', 'Administrateur']].map(([key, label]) => (
                <button key={key} type="button" onClick={() => setRole(key)}
                  className="text-xs px-2.5 py-1 rounded-lg font-medium transition-colors"
                  style={role === key
                    ? { background: `${MODULE_COLOR}26`, color: MODULE_COLOR, border: `1px solid ${MODULE_COLOR}59` }
                    : { background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}
                >{label}</button>
              ))}
            </div>
          </div>
          {role === 'analyst' && (
            <div>
              <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Modules accessibles</label>
              <label className="flex items-center gap-2 text-sm cursor-pointer mb-2" style={{ color: 'var(--text-secondary)' }}>
                <input type="checkbox" checked={fullAccess} onChange={e => setFullAccess(e.target.checked)}
                  className="w-3.5 h-3.5" style={{ accentColor: MODULE_COLOR }} />
                Accès à tout (par défaut)
              </label>
              {!fullAccess && (
                <div className="rounded-lg p-3 space-y-2.5 max-h-56 overflow-y-auto"
                  style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)' }}>
                  {MODULE_PAGE_TREE.map(mod => {
                    const allSelected = mod.pages.every(p => selectedPages.has(p.to))
                    const someSelected = mod.pages.some(p => selectedPages.has(p.to))
                    return (
                      <div key={mod.key}>
                        <label className="flex items-center gap-2 text-xs font-semibold cursor-pointer" style={{ color: mod.color }}>
                          <input type="checkbox" checked={allSelected}
                            ref={el => { if (el) el.indeterminate = someSelected && !allSelected }}
                            onChange={() => toggleModule(mod.pages, allSelected)}
                            className="w-3.5 h-3.5" style={{ accentColor: mod.color }} />
                          {mod.label}
                        </label>
                        <div className="pl-5 mt-1 space-y-1">
                          {mod.pages.map(p => (
                            <label key={p.to} className="flex items-center gap-2 text-xs cursor-pointer" style={{ color: 'var(--text-secondary)' }}>
                              <input type="checkbox" checked={selectedPages.has(p.to)} onChange={() => togglePage(p.to)}
                                className="w-3 h-3" style={{ accentColor: mod.color }} />
                              {p.label}
                            </label>
                          ))}
                        </div>
                      </div>
                    )
                  })}
                </div>
              )}
              <p className="text-xs mt-1.5" style={{ color: 'var(--text-faint)' }}>
                Paramètres (dont son propre compte/déconnexion) reste toujours accessible, quels que soient les modules cochés.
              </p>
            </div>
          )}
          {isEdit && (
            <>
              <label className="flex items-center gap-2 text-sm cursor-pointer" style={{ color: 'var(--text-secondary)' }}>
                <input type="checkbox" checked={isActive} onChange={e => setIsActive(e.target.checked)}
                  className="w-3.5 h-3.5" style={{ accentColor: MODULE_COLOR }} />
                Compte actif
              </label>
              <label className="flex items-center gap-2 text-sm cursor-pointer" style={{ color: 'var(--text-secondary)' }}>
                <input type="checkbox" checked={forceReset} onChange={e => setForceReset(e.target.checked)}
                  className="w-3.5 h-3.5" style={{ accentColor: MODULE_COLOR }} />
                Forcer le changement de mot de passe à la prochaine connexion
              </label>
            </>
          )}
          {error && <p className="text-xs" style={{ color: '#f85149' }}>{error}</p>}
          <div className="flex justify-end gap-2 pt-1">
            <button onClick={onClose}
              className="text-xs px-3 py-2 rounded-lg font-medium"
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}
            >Annuler</button>
            <button onClick={confirm} disabled={!canSubmit || saving}
              className="text-xs px-3 py-2 rounded-lg font-medium disabled:opacity-50"
              style={{ background: `${MODULE_COLOR}26`, color: MODULE_COLOR, border: `1px solid ${MODULE_COLOR}59` }}
            >{saving ? 'Enregistrement…' : (isEdit ? 'Enregistrer' : 'Ajouter')}</button>
          </div>
        </div>
      </div>
    </div>
  )
}

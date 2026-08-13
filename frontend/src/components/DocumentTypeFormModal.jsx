import { useState } from 'react'
import { MODULES } from '../constants/modules.js'

const MODULE_COLOR = MODULES.documentation.color

// Ajout d'un type de document (PSSI, Charte Administrateur...) — registre ouvert spécifique au
// module Documentation, calqué sur AnalystFormModal.jsx.
export default function DocumentTypeFormModal({ onConfirm, onClose }) {
  const [name, setName] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  async function confirm() {
    if (!name.trim() || saving) return
    setSaving(true)
    setError('')
    try {
      await onConfirm({ name: name.trim() })
    } catch (e) {
      setError(e?.response?.data?.detail || "Impossible d'ajouter ce type de document.")
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 modal-backdrop animate-backdrop-in" onClick={onClose}>
      <div className="max-w-md w-full rounded-2xl flex flex-col animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
          <h2 className="font-semibold" style={{ color: MODULE_COLOR }}>Ajouter un type de document</h2>
          <button onClick={onClose} className="p-1.5 rounded-lg" style={{ color: 'var(--text-muted)' }}>
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>
        <div className="p-6 space-y-3">
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Nom</label>
            <input autoFocus value={name} onChange={e => setName(e.target.value)}
              placeholder="Ex : Plan de continuité d'activité"
              className="w-full text-sm rounded-lg px-3 py-2 outline-none"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }} />
          </div>
          {error && <p className="text-xs" style={{ color: '#f85149' }}>{error}</p>}
          <div className="flex justify-end gap-2 pt-1">
            <button onClick={onClose}
              className="text-xs px-3 py-2 rounded-lg font-medium"
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}
            >Annuler</button>
            <button onClick={confirm} disabled={!name.trim() || saving}
              className="text-xs px-3 py-2 rounded-lg font-medium disabled:opacity-50"
              style={{ background: `${MODULE_COLOR}26`, color: MODULE_COLOR, border: `1px solid ${MODULE_COLOR}59` }}
            >{saving ? 'Enregistrement…' : 'Ajouter'}</button>
          </div>
        </div>
      </div>
    </div>
  )
}

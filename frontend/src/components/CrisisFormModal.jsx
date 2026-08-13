import { useState } from 'react'
import { useAnalysts } from '../contexts/AnalystContext.jsx'
import { MODULES } from '../constants/modules.js'

const MODULE_COLOR = MODULES.incidents.color

// Activation d'une crise — toujours un acte humain explicite (cf. backend/models.py::Crisis,
// activated_at/activated_by obligatoires). La création EST l'activation, pas une étape séparée.
export default function CrisisFormModal({ onSave, onClose }) {
  const { names: ANALYSTS } = useAnalysts()
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [activatedBy, setActivatedBy] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  async function confirm() {
    if (!title.trim() || !activatedBy || saving) return
    setSaving(true)
    setError('')
    try {
      await onSave({ title: title.trim(), description: description.trim() || null, activated_by: activatedBy })
    } catch (e) {
      setError(e?.response?.data?.detail || "Impossible d'activer cette crise.")
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 modal-backdrop animate-backdrop-in" onClick={onClose}>
      <div className="max-w-md w-full rounded-2xl flex flex-col animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
          <h2 className="font-semibold" style={{ color: MODULE_COLOR }}>Activer une crise</h2>
          <button onClick={onClose} className="p-1.5 rounded-lg" style={{ color: 'var(--text-muted)' }}>
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>
        <div className="p-6 space-y-3">
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Titre</label>
            <input autoFocus value={title} onChange={e => setTitle(e.target.value)}
              placeholder="Ex : Ransomware sur le SI de production"
              className="w-full text-sm rounded-lg px-3 py-2 outline-none"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }} />
          </div>
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Description (optionnel)</label>
            <textarea value={description} onChange={e => setDescription(e.target.value)} rows={3}
              placeholder="Contexte, périmètre estimé…"
              className="w-full text-sm rounded-lg px-3 py-2 outline-none resize-none"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }} />
          </div>
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Activée par</label>
            <select value={activatedBy} onChange={e => setActivatedBy(e.target.value)}
              className="w-full text-sm rounded-lg px-3 py-2 outline-none"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}>
              <option value="">Sélectionner…</option>
              {ANALYSTS.map(name => <option key={name} value={name}>{name}</option>)}
            </select>
          </div>
          {error && <p className="text-xs" style={{ color: '#f85149' }}>{error}</p>}
          <div className="flex justify-end gap-2 pt-1">
            <button onClick={onClose}
              className="text-xs px-3 py-2 rounded-lg font-medium"
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}
            >Annuler</button>
            <button onClick={confirm} disabled={!title.trim() || !activatedBy || saving}
              className="text-xs px-3 py-2 rounded-lg font-medium disabled:opacity-50"
              style={{ background: `${MODULE_COLOR}26`, color: MODULE_COLOR, border: `1px solid ${MODULE_COLOR}59` }}
            >{saving ? 'Activation…' : 'Activer la crise'}</button>
          </div>
        </div>
      </div>
    </div>
  )
}

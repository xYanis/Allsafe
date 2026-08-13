import { useEffect, useState } from 'react'
import { crises as fetchActiveCrises, createCrisis, linkCrisisIncident, getIncident } from '../api/client.js'
import { useAnalysts } from '../contexts/AnalystContext.jsx'
import { MODULES } from '../constants/modules.js'

const MODULE_COLOR = MODULES.incidents.color

// Lien bidirectionnel Incident -> Crisis (le sens inverse, rattacher un incident depuis une
// crise, existe déjà sur CrisisDetailModal.jsx). Pas de nouvel endpoint backend : compose
// createCrisis + linkCrisisIncident (ou juste linkCrisisIncident sur une crise existante),
// puis rafraîchit l'incident pour récupérer crisis_id/crisis_title à jour.
export default function EscalateToCrisisModal({ incident, onClose, onEscalated }) {
  const { names: ANALYSTS } = useAnalysts()
  const [activeCrises, setActiveCrises] = useState(null) // null = chargement
  const [mode, setMode] = useState('new') // 'new' | 'existing'
  const [title, setTitle] = useState(`Escalade depuis l'incident « ${incident.title} »`)
  const [existingCrisisId, setExistingCrisisId] = useState('')
  const [by, setBy] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    fetchActiveCrises({ status: 'active' })
      .then(r => {
        const items = r.data.items || []
        setActiveCrises(items)
        if (items.length === 0) setMode('new')
      })
      .catch(() => setActiveCrises([]))
  }, [])

  async function confirm() {
    if (!by || saving) return
    if (mode === 'new' && !title.trim()) return
    if (mode === 'existing' && !existingCrisisId) return
    setSaving(true)
    setError('')
    try {
      let crisisId = existingCrisisId
      if (mode === 'new') {
        const { data: created } = await createCrisis({ title: title.trim(), activated_by: by })
        crisisId = created.id
      }
      await linkCrisisIncident(crisisId, incident.id, by)
      const { data: freshIncident } = await getIncident(incident.id)
      onEscalated(freshIncident)
    } catch (e) {
      setError(e?.response?.data?.detail || "Impossible d'escalader cet incident en crise.")
      setSaving(false)
    }
  }

  const invalid = !by || (mode === 'new' ? !title.trim() : !existingCrisisId)

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 modal-backdrop animate-backdrop-in" onClick={onClose}>
      <div className="max-w-md w-full rounded-2xl flex flex-col animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4" style={{ borderBottom: '1px solid var(--border)' }}>
          <div className="flex items-center justify-between">
            <h2 className="font-semibold" style={{ color: MODULE_COLOR }}>🚨 Escalader en crise</h2>
            <button onClick={onClose} className="p-1.5 rounded-lg" style={{ color: 'var(--text-muted)' }}>
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
            </button>
          </div>
          <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>{incident.title}</p>
        </div>

        <div className="p-6 space-y-3">
          {activeCrises === null ? (
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Chargement…</p>
          ) : (
            <>
              {activeCrises.length > 0 && (
                <div className="flex gap-2">
                  {[['new', 'Nouvelle crise'], ['existing', 'Crise active existante']].map(([v, label]) => (
                    <button key={v} onClick={() => setMode(v)} type="button"
                      className="text-xs px-3 py-1.5 rounded-lg font-medium flex-1"
                      style={mode === v
                        ? { background: `${MODULE_COLOR}26`, color: MODULE_COLOR, border: `1px solid ${MODULE_COLOR}59` }
                        : { background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}>
                      {label}
                    </button>
                  ))}
                </div>
              )}

              {mode === 'new' ? (
                <div>
                  <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Titre de la crise</label>
                  <input autoFocus value={title} onChange={e => setTitle(e.target.value)}
                    className="w-full text-sm rounded-lg px-3 py-2 outline-none"
                    style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }} />
                </div>
              ) : (
                <div>
                  <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Crise active</label>
                  {activeCrises.length === 0 ? (
                    <p className="text-xs" style={{ color: 'var(--text-faint)' }}>Aucune crise active — créez-en une nouvelle.</p>
                  ) : (
                    <select value={existingCrisisId} onChange={e => setExistingCrisisId(e.target.value)}
                      className="w-full text-sm rounded-lg px-3 py-2 outline-none"
                      style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}>
                      <option value="">Sélectionner…</option>
                      {activeCrises.map(c => <option key={c.id} value={c.id}>{c.title}</option>)}
                    </select>
                  )}
                </div>
              )}

              <div>
                <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Par</label>
                <select value={by} onChange={e => setBy(e.target.value)}
                  className="w-full text-sm rounded-lg px-3 py-2 outline-none"
                  style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}>
                  <option value="">Sélectionner…</option>
                  {ANALYSTS.map(name => <option key={name} value={name}>{name}</option>)}
                </select>
              </div>
            </>
          )}
          {error && <p className="text-xs" style={{ color: '#f85149' }}>{error}</p>}
          <div className="flex justify-end gap-2 pt-1">
            <button onClick={onClose}
              className="text-xs px-3 py-2 rounded-lg font-medium"
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}
            >Annuler</button>
            <button onClick={confirm} disabled={invalid || saving || activeCrises === null}
              className="text-xs px-3 py-2 rounded-lg font-medium disabled:opacity-50"
              style={{ background: `${MODULE_COLOR}26`, color: MODULE_COLOR, border: `1px solid ${MODULE_COLOR}59` }}
            >{saving ? 'Escalade…' : 'Escalader'}</button>
          </div>
        </div>
      </div>
    </div>
  )
}

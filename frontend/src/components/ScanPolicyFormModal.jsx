import { useState } from 'react'
import { MODULES } from '../constants/modules.js'

const MODULE_COLOR = MODULES.parametres.color

export const SCAN_POLICY_CRITICITE_LABELS = { critique: 'Critique', haute: 'Haute', moyenne: 'Moyenne', faible: 'Faible' }
export const SCAN_POLICY_WEEKDAY_LABELS = ['Lundi', 'Mardi', 'Mercredi', 'Jeudi', 'Vendredi', 'Samedi', 'Dimanche']
const CRITICITE_LABELS = SCAN_POLICY_CRITICITE_LABELS
const WEEKDAY_LABELS = SCAN_POLICY_WEEKDAY_LABELS

const inputStyle = { background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }

// Édition d'une politique de scan planifié (17/08/2026) — jeu de 4 lignes fixe (une par
// criticité, cf. models.py::ScanPolicy), toujours en modification, jamais de création.
export default function ScanPolicyFormModal({ initial, onConfirm, onClose }) {
  const [enabled, setEnabled] = useState(initial.enabled)
  const [frequency, setFrequency] = useState(initial.frequency)
  const [hour, setHour] = useState(initial.hour)
  const [weekday, setWeekday] = useState(initial.weekday ?? 6)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  async function confirm() {
    if (saving) return
    setSaving(true)
    setError('')
    try {
      await onConfirm({ enabled, frequency, hour, weekday: frequency === 'weekly' ? weekday : null })
    } catch (e) {
      setError(e?.response?.data?.detail || 'Impossible d\'enregistrer cette politique.')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 modal-backdrop animate-backdrop-in" onClick={onClose}>
      <div className="max-w-md w-full rounded-2xl flex flex-col animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
          <h2 className="font-semibold" style={{ color: MODULE_COLOR }}>
            Politique de scan — {CRITICITE_LABELS[initial.criticite] || initial.criticite}
          </h2>
          <button onClick={onClose} className="p-1.5 rounded-lg" style={{ color: 'var(--text-muted)' }}>
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>
        <div className="p-6 space-y-3">
          <label className="flex items-center gap-2 cursor-pointer select-none">
            <input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} className="w-3.5 h-3.5" style={{ accentColor: MODULE_COLOR }} />
            <span className="text-sm" style={{ color: 'var(--text-primary)' }}>Activée</span>
          </label>
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Fréquence</label>
            <select value={frequency} onChange={e => setFrequency(e.target.value)}
              className="w-full text-sm rounded-lg px-3 py-2 outline-none" style={inputStyle}>
              <option value="daily">Quotidienne</option>
              <option value="weekly">Hebdomadaire</option>
            </select>
          </div>
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Heure</label>
            <select value={hour} onChange={e => setHour(Number(e.target.value))}
              className="w-full text-sm rounded-lg px-3 py-2 outline-none" style={inputStyle}>
              {Array.from({ length: 24 }, (_, h) => <option key={h} value={h}>{String(h).padStart(2, '0')}h00</option>)}
            </select>
          </div>
          {frequency === 'weekly' && (
            <div>
              <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Jour</label>
              <select value={weekday} onChange={e => setWeekday(Number(e.target.value))}
                className="w-full text-sm rounded-lg px-3 py-2 outline-none" style={inputStyle}>
                {WEEKDAY_LABELS.map((label, i) => <option key={i} value={i}>{label}</option>)}
              </select>
            </div>
          )}
          {error && <p className="text-xs" style={{ color: '#f85149' }}>{error}</p>}
          <div className="flex justify-end gap-2 pt-1">
            <button onClick={onClose}
              className="text-xs px-3 py-2 rounded-lg font-medium"
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}
            >Annuler</button>
            <button onClick={confirm} disabled={saving}
              className="text-xs px-3 py-2 rounded-lg font-medium disabled:opacity-50"
              style={{ background: `${MODULE_COLOR}26`, color: MODULE_COLOR, border: `1px solid ${MODULE_COLOR}59` }}
            >{saving ? 'Enregistrement…' : 'Enregistrer'}</button>
          </div>
        </div>
      </div>
    </div>
  )
}

import { useState } from 'react'
import { useAnalysts } from '../contexts/AnalystContext.jsx'
import AssetDropdown from './AssetDropdown.jsx'
import { MODULES } from '../constants/modules.js'

// Vocabulaire du module Incidents — listes fixes (V1), miroir exact de
// services/nis2_deadlines.py (CATEGORIES/SEVERITIES/STATUSES) côté backend. Pas
// d'endpoint pour les récupérer : même convention que les sévérités/statuts de
// veille, codés en dur des deux côtés (cf. Watch.jsx).
export const INCIDENT_CATEGORIES = [
  { value: 'ransomware', label: 'Ransomware' },
  { value: 'data_breach', label: 'Fuite de données' },
  { value: 'intrusion', label: 'Intrusion' },
  { value: 'dos', label: 'Déni de service' },
  { value: 'phishing', label: 'Hameçonnage' },
  { value: 'malware', label: 'Logiciel malveillant' },
  { value: 'misconfiguration', label: 'Erreur de configuration' },
  { value: 'other', label: 'Autre' },
]
export const INCIDENT_SEVERITIES = [
  { value: 'critical', label: 'Critique' },
  { value: 'major', label: 'Majeur' },
  { value: 'minor', label: 'Mineur' },
]
export const INCIDENT_STATUSES = [
  { value: 'declared', label: 'Déclaré' },
  { value: 'in_progress', label: 'En cours' },
  { value: 'contained', label: 'Contenu' },
  { value: 'resolved', label: 'Résolu' },
  { value: 'closed', label: 'Clôturé' },
]

const MODULE_COLOR = MODULES.incidents.color

function toLocalInput(iso) {
  const d = iso ? new Date(iso) : new Date()
  const pad = n => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
}

const inputStyle = { background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }
const labelClass = 'text-xs font-semibold uppercase tracking-wide block mb-1.5'

// Création (depuis zéro ou préremplie via /prefill) et édition — même modale,
// `initial.id` distingue les deux (cf. Incidents.jsx).
export default function IncidentFormModal({ initial, assetList, onSave, onClose }) {
  const { names: ANALYSTS } = useAnalysts()
  const [title, setTitle] = useState(initial?.title || '')
  const [description, setDescription] = useState(initial?.description || '')
  const [category, setCategory] = useState(initial?.category || 'intrusion')
  const [severity, setSeverity] = useState(initial?.severity || 'major')
  const [status, setStatus] = useState(initial?.status || 'declared')
  const [awareAt, setAwareAt] = useState(toLocalInput(initial?.aware_at))
  const [reportedBy, setReportedBy] = useState(initial?.reported_by || '')
  const [assetIds, setAssetIds] = useState(initial?.affected_asset_ids || [])
  const [saving, setSaving] = useState(false)

  const isEdit = Boolean(initial?.id)
  const isPrefilled = !isEdit && Boolean(initial?.security_event_id || initial?.vulnerability_id || initial?.watch_item_id)
  const missing = !title.trim() || !reportedBy || !awareAt

  async function save() {
    if (missing || saving) return
    setSaving(true)
    try {
      await onSave({
        title: title.trim(),
        description: description.trim() || null,
        category, severity, status,
        aware_at: new Date(awareAt).toISOString(),
        reported_by: reportedBy,
        affected_asset_ids: assetIds,
        ...(initial?.security_event_id ? { security_event_id: initial.security_event_id } : {}),
        ...(initial?.vulnerability_id ? { vulnerability_id: initial.vulnerability_id } : {}),
        ...(initial?.watch_item_id ? { watch_item_id: initial.watch_item_id } : {}),
      })
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 animate-backdrop-in modal-backdrop" onClick={onClose}>
      <div className="max-w-lg w-full rounded-2xl flex flex-col max-h-[90vh] animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4 flex items-center justify-between flex-shrink-0" style={{ borderBottom: '1px solid var(--border)' }}>
          <h2 className="font-semibold" style={{ color: MODULE_COLOR }}>{isEdit ? "Modifier l'incident" : 'Déclarer un incident'}</h2>
          <button onClick={onClose} className="p-1.5 rounded-lg" style={{ color: 'var(--text-muted)' }}>
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>

        <div className="p-6 space-y-3 overflow-y-auto">
          {isPrefilled && (
            <p className="text-xs px-2.5 py-1.5 rounded-lg" style={{ background: `${MODULE_COLOR}1a`, color: MODULE_COLOR, border: `1px solid ${MODULE_COLOR}40` }}>
              Préempli depuis {initial.security_event_id ? 'une alerte de déception' : initial.vulnerability_id ? 'une vulnérabilité' : 'un item de veille'} — vérifiez les champs avant de créer. Rien n'est créé tant que vous ne validez pas.
            </p>
          )}

          <div>
            <label className={labelClass} style={{ color: 'var(--text-muted)' }}>Titre</label>
            <input value={title} onChange={e => setTitle(e.target.value)} autoFocus
              className="w-full text-sm rounded-lg px-3 py-2 outline-none" style={inputStyle} />
          </div>

          <div>
            <label className={labelClass} style={{ color: 'var(--text-muted)' }}>Description</label>
            <textarea value={description} onChange={e => setDescription(e.target.value)} rows={3}
              className="w-full text-sm rounded-lg px-3 py-2 outline-none resize-none" style={inputStyle} />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className={labelClass} style={{ color: 'var(--text-muted)' }}>Catégorie</label>
              <select value={category} onChange={e => setCategory(e.target.value)} className="w-full text-sm rounded-lg px-3 py-2 outline-none" style={inputStyle}>
                {INCIDENT_CATEGORIES.map(c => <option key={c.value} value={c.value}>{c.label}</option>)}
              </select>
            </div>
            <div>
              <label className={labelClass} style={{ color: 'var(--text-muted)' }}>Sévérité</label>
              <select value={severity} onChange={e => setSeverity(e.target.value)} className="w-full text-sm rounded-lg px-3 py-2 outline-none" style={inputStyle}>
                {INCIDENT_SEVERITIES.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
              </select>
            </div>
          </div>

          {isEdit && (
            <div>
              <label className={labelClass} style={{ color: 'var(--text-muted)' }}>Statut</label>
              <select value={status} onChange={e => setStatus(e.target.value)} className="w-full text-sm rounded-lg px-3 py-2 outline-none" style={inputStyle}>
                {INCIDENT_STATUSES.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
              </select>
            </div>
          )}

          <div>
            <label className={labelClass} style={{ color: 'var(--text-muted)' }}>Prise de connaissance</label>
            <input type="datetime-local" value={awareAt} onChange={e => setAwareAt(e.target.value)}
              className="w-full text-sm rounded-lg px-3 py-2 outline-none" style={inputStyle}
              disabled={isEdit && initial?.aware_at_locked} />
            <p className="text-xs mt-1" style={{ color: 'var(--text-faint)' }}>
              Point de départ légal des délais NIS 2 (Art. 23){isEdit && initial?.aware_at_locked
                ? ' — verrouillé, un jalon de notification a déjà été envoyé.'
                : '.'}
            </p>
          </div>

          <div>
            <label className={labelClass} style={{ color: 'var(--text-muted)' }}>Déclaré par</label>
            <select value={reportedBy} onChange={e => setReportedBy(e.target.value)} className="w-full text-sm rounded-lg px-3 py-2 outline-none" style={inputStyle}>
              <option value="">Sélectionner un analyste…</option>
              {ANALYSTS.map(name => <option key={name} value={name}>{name}</option>)}
            </select>
          </div>

          <div>
            <label className={labelClass} style={{ color: 'var(--text-muted)' }}>Actifs concernés</label>
            <AssetDropdown assetList={assetList} selected={assetIds} onChange={setAssetIds} />
          </div>

          <div className="flex justify-end gap-2 pt-1">
            <button onClick={onClose} className="text-xs px-3 py-2 rounded-lg font-medium"
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}>Annuler</button>
            <button onClick={save} disabled={missing || saving}
              className="text-xs px-3 py-2 rounded-lg font-medium disabled:opacity-50"
              style={{ background: `${MODULE_COLOR}26`, color: MODULE_COLOR, border: `1px solid ${MODULE_COLOR}59` }}>
              {saving ? 'Enregistrement…' : isEdit ? 'Enregistrer' : "Créer l'incident"}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

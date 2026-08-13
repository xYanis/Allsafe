import { useState } from 'react'
import { useAnalysts } from '../contexts/AnalystContext.jsx'
import AssetDropdown from './AssetDropdown.jsx'

// Modale de création d'un audit — le cadrage/l'autorisation (scope, règles d'engagement,
// mandataire) se posent séparément une fois l'audit créé (AuditAuthorizeCard dans
// AuditDetail.jsx) : POST /audits/{id}/authorize, immuable une fois posé, cf. docs/AUDITS.md.
export const AUDIT_TYPES = [
  { value: 'architecture', label: 'Architecture' },
  { value: 'configuration', label: 'Configuration' },
  { value: 'code', label: 'Code source' },
  { value: 'pentest', label: "Test d'intrusion" },
  { value: 'redteam', label: 'Red Team' },
]
export const AUDIT_METHODOLOGIES = [
  { value: 'boite_noire', label: 'Boîte noire' },
  { value: 'boite_grise', label: 'Boîte grise' },
  { value: 'boite_blanche', label: 'Boîte blanche' },
]
export const AUDIT_STATUSES = [
  { value: 'cadrage', label: 'Cadrage' },
  { value: 'autorise', label: 'Autorisé' },
  { value: 'en_cours', label: 'En cours' },
  { value: 'termine', label: 'Terminé' },
  { value: 'archive', label: 'Archivé' },
]

export default function AuditFormModal({ assetList, onClose, onSaved }) {
  const { names } = useAnalysts()
  const [title, setTitle] = useState('')
  const [type, setType] = useState('pentest')
  const [methodology, setMethodology] = useState('')
  const [referential, setReferential] = useState('')
  const [conductedBy, setConductedBy] = useState('')
  const [startedAt, setStartedAt] = useState('')
  const [endedAt, setEndedAt] = useState('')
  const [assetIds, setAssetIds] = useState([])
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const missing = !title.trim() || !type

  async function handleSubmit() {
    if (missing || saving) return
    setSaving(true)
    setError('')
    try {
      await onSaved({
        title: title.trim(),
        type,
        methodology: methodology || null,
        referential: referential.trim() || null,
        conducted_by: conductedBy || null,
        started_at: startedAt ? new Date(startedAt).toISOString() : null,
        ended_at: endedAt ? new Date(endedAt).toISOString() : null,
        asset_ids: assetIds,
      })
    } catch (e) {
      setError(e?.response?.data?.detail || 'Erreur lors de la création.')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 animate-backdrop-in modal-backdrop" onClick={onClose}>
      <div className="max-w-lg w-full rounded-2xl flex flex-col animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
          <h2 className="font-semibold" style={{ color: 'var(--text-primary)' }}>Nouvel audit</h2>
          <button onClick={onClose} className="p-1.5 rounded-lg" style={{ color: 'var(--text-muted)' }}>
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>
        <div className="p-6 space-y-3 max-h-[70vh] overflow-y-auto">
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Titre</label>
            <input autoFocus value={title} onChange={e => setTitle(e.target.value)} placeholder="ex : Audit de code — Application Allsafe"
              className="w-full text-sm rounded-lg px-3 py-2 outline-none"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }} />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Type</label>
              <select value={type} onChange={e => setType(e.target.value)}
                className="w-full text-sm rounded-lg px-3 py-2 outline-none"
                style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}>
                {AUDIT_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
              </select>
            </div>
            <div>
              <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Méthodologie</label>
              <select value={methodology} onChange={e => setMethodology(e.target.value)}
                className="w-full text-sm rounded-lg px-3 py-2 outline-none"
                style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}>
                <option value="">—</option>
                {AUDIT_METHODOLOGIES.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
              </select>
            </div>
          </div>
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Référentiel</label>
            <input value={referential} onChange={e => setReferential(e.target.value)} placeholder="ex : OWASP ASVS, CIS, PTES, ANSSI…"
              className="w-full text-sm rounded-lg px-3 py-2 outline-none"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }} />
          </div>
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Conduit par</label>
            <select value={conductedBy} onChange={e => setConductedBy(e.target.value)}
              className="w-full text-sm rounded-lg px-3 py-2 outline-none"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}>
              <option value="">Sélectionner un analyste…</option>
              {names.map(n => <option key={n} value={n}>{n}</option>)}
            </select>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Début</label>
              <input type="date" value={startedAt} onChange={e => setStartedAt(e.target.value)}
                className="w-full text-sm rounded-lg px-3 py-2 outline-none"
                style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }} />
            </div>
            <div>
              <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Fin</label>
              <input type="date" value={endedAt} onChange={e => setEndedAt(e.target.value)}
                className="w-full text-sm rounded-lg px-3 py-2 outline-none"
                style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }} />
            </div>
          </div>
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Actifs ciblés</label>
            <AssetDropdown assetList={assetList} selected={assetIds} onChange={setAssetIds} />
            <p className="text-xs mt-1" style={{ color: 'var(--text-faint, var(--text-muted))' }}>Optionnel — peut être précisé plus tard.</p>
          </div>
          {error && <p className="text-xs" style={{ color: '#f85149' }}>{error}</p>}
          <div className="flex justify-end gap-2 pt-1">
            <button onClick={onClose} className="text-xs px-3 py-2 rounded-lg font-medium"
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}>Annuler</button>
            <button onClick={handleSubmit} disabled={missing || saving}
              className="text-xs px-3 py-2 rounded-lg font-medium disabled:opacity-50"
              style={{ background: 'rgba(63,185,80,0.15)', color: '#3fb950', border: '1px solid rgba(63,185,80,0.4)' }}>
              {saving ? 'Création…' : 'Créer l’audit'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

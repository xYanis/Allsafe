import { useState } from 'react'
import { useAnalysts } from '../contexts/AnalystContext.jsx'
import { MODULES } from '../constants/modules.js'

const MODULE_COLOR = MODULES.incidents.color

// Rôles suggérés (datalist, pas une liste fermée) — vocabulaire courant d'une cellule de
// crise, mais un rôle spécifique à l'organisation reste saisissable librement.
const SUGGESTED_ROLES = ['Décideur', 'Communication', 'Technique', 'Juridique', 'RH']

const CONFIG = {
  'stand-down': {
    title: 'Désactiver la crise',
    confirmLabel: 'Désactiver',
    fields: ['content', 'analyst'],
    contentLabel: 'Justification',
    contentPlaceholder: 'Ex : périmètre contenu, remédiation en cours, retour à la normale…',
  },
  decision: {
    title: 'Consigner une décision',
    confirmLabel: 'Consigner',
    fields: ['content', 'analyst'],
    contentLabel: 'Décision',
    contentPlaceholder: 'Ex : bascule sur le site de secours, arrêt du service X…',
  },
  communication: {
    title: 'Consigner une communication',
    confirmLabel: 'Consigner',
    fields: ['content', 'audience', 'analyst'],
    contentLabel: 'Contenu',
    contentPlaceholder: 'Ex : message envoyé aux équipes, communiqué transmis…',
  },
  role: {
    title: 'Assigner un rôle',
    confirmLabel: 'Assigner',
    fields: ['role', 'analystName', 'analyst'],
  },
}

// Modale unique pour les 4 actions de la cellule de crise (désactivation, décision,
// communication, rôle) — mêmes champs de base (contenu + analyste), champs additionnels
// selon `kind`. Ne fusionne pas avec AnnotationModal.jsx (vulnérabilités/incidents) : les
// formes divergent trop (audience, rôle+2 analystes) pour justifier d'alourdir un composant
// déjà largement partagé ailleurs.
export default function CrisisActionModal({ kind, subtitle, onConfirm, onClose }) {
  const { names: ANALYSTS } = useAnalysts()
  const cfg = CONFIG[kind]
  const [content, setContent] = useState('')
  const [audience, setAudience] = useState('interne')
  const [role, setRole] = useState('')
  const [analystName, setAnalystName] = useState('')
  const [analyst, setAnalyst] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const needsContent = cfg.fields.includes('content')
  const needsRole = cfg.fields.includes('role')
  const needsAnalystName = cfg.fields.includes('analystName')

  const invalid = (needsContent && !content.trim())
    || (needsRole && (!role.trim() || !analystName))
    || !analyst

  async function confirm() {
    if (invalid || saving) return
    setSaving(true)
    setError('')
    try {
      if (kind === 'stand-down') await onConfirm({ justification: content.trim(), analyst })
      else if (kind === 'decision') await onConfirm({ content: content.trim(), author: analyst })
      else if (kind === 'communication') await onConfirm({ content: content.trim(), audience, author: analyst })
      else if (kind === 'role') await onConfirm({ role: role.trim(), analyst_name: analystName, by: analyst })
    } catch (e) {
      setError(e?.response?.data?.detail || "Impossible d'enregistrer cette action.")
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 modal-backdrop animate-backdrop-in" onClick={onClose}>
      <div className="max-w-md w-full rounded-2xl flex flex-col animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4" style={{ borderBottom: '1px solid var(--border)' }}>
          <div className="flex items-center justify-between">
            <h2 className="font-semibold" style={{ color: MODULE_COLOR }}>{cfg.title}</h2>
            <button onClick={onClose} className="p-1.5 rounded-lg" style={{ color: 'var(--text-muted)' }}>
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
            </button>
          </div>
          {subtitle && <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>{subtitle}</p>}
        </div>
        <div className="p-6 space-y-3">
          {needsRole && (
            <>
              <div>
                <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Rôle</label>
                <input list="crisis-roles" value={role} onChange={e => setRole(e.target.value)}
                  placeholder="Ex : Communication"
                  className="w-full text-sm rounded-lg px-3 py-2 outline-none"
                  style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }} />
                <datalist id="crisis-roles">
                  {SUGGESTED_ROLES.map(r => <option key={r} value={r} />)}
                </datalist>
              </div>
              <div>
                <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Analyste assigné</label>
                <select value={analystName} onChange={e => setAnalystName(e.target.value)}
                  className="w-full text-sm rounded-lg px-3 py-2 outline-none"
                  style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}>
                  <option value="">Sélectionner…</option>
                  {ANALYSTS.map(name => <option key={name} value={name}>{name}</option>)}
                </select>
              </div>
            </>
          )}
          {needsContent && (
            <div>
              <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>{cfg.contentLabel}</label>
              <textarea autoFocus value={content} onChange={e => setContent(e.target.value)} rows={4}
                placeholder={cfg.contentPlaceholder}
                className="w-full text-sm rounded-lg px-3 py-2 outline-none resize-none"
                style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }} />
            </div>
          )}
          {cfg.fields.includes('audience') && (
            <div>
              <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Audience</label>
              <div className="flex gap-2">
                {[['interne', 'Interne'], ['externe', 'Externe']].map(([v, label]) => (
                  <button key={v} onClick={() => setAudience(v)} type="button"
                    className="text-xs px-3 py-1.5 rounded-lg font-medium"
                    style={audience === v
                      ? { background: `${MODULE_COLOR}26`, color: MODULE_COLOR, border: `1px solid ${MODULE_COLOR}59` }
                      : { background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}>
                    {label}
                  </button>
                ))}
              </div>
            </div>
          )}
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>
              {needsRole ? 'Assigné par' : 'Par'}
            </label>
            <select value={analyst} onChange={e => setAnalyst(e.target.value)}
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
            <button onClick={confirm} disabled={invalid || saving}
              className="text-xs px-3 py-2 rounded-lg font-medium disabled:opacity-50"
              style={{ background: `${MODULE_COLOR}26`, color: MODULE_COLOR, border: `1px solid ${MODULE_COLOR}59` }}
            >{saving ? 'Enregistrement…' : cfg.confirmLabel}</button>
          </div>
        </div>
      </div>
    </div>
  )
}

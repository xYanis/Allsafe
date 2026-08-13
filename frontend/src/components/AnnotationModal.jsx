import { useState } from 'react'
import { useAnalysts } from '../contexts/AnalystContext.jsx'

// Modale générique de saisie d'annotation, réutilisée pour les actions
// "⏳ En attente d'un patch correctif", "🚫 Faux positif" et "✓ Corrigé" du
// Dashboard. Exige toujours de désigner l'analyste — on doit pouvoir savoir
// qui a qualifié une vuln, pas seulement pourquoi. L'annotation elle-même
// n'est obligatoire que pour "en attente"/"faux positif" (`noteRequired`,
// true par défaut) : "Corrigé" reste une action rapide sur du non-CRITICAL,
// l'annotation n'y est qu'un complément optionnel (cf. CLAUDE.md).
export default function AnnotationModal({ title, detail, color, subtitle, helpText, placeholder, confirmLabel, onConfirm, onClose, noteRequired = true, initialNote = '', initialValidator = '', showReviewDate = false, initialReviewDate = '' }) {
  // `names` bascule déjà sur FAKE_VALIDATORS en mode Présentation, centralisé dans
  // AnalystContext.jsx (31/07/2026) — plus besoin de le refaire ici.
  const { names } = useAnalysts()
  const [note, setNote] = useState(initialNote)
  const [validator, setValidator] = useState(initialValidator)
  const [reviewDate, setReviewDate] = useState(initialReviewDate)
  const [saving, setSaving] = useState(false)

  const noteMissing = noteRequired && !note.trim()
  const reviewDateMissing = showReviewDate && !reviewDate

  async function confirm() {
    if (noteMissing || !validator || reviewDateMissing || saving) return
    setSaving(true)
    try {
      await onConfirm(note.trim() || null, validator, showReviewDate ? reviewDate : undefined)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 animate-backdrop-in modal-backdrop" onClick={onClose}>
      <div className="max-w-lg w-full rounded-2xl flex flex-col animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
          <div>
            <h2 className="font-semibold font-mono" style={{ color }}>{title}</h2>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{subtitle}{detail ? ` — ${detail}` : ''}</p>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg" style={{ color: 'var(--text-muted)' }}>
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>
        <div className="p-6 space-y-3">
          <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>{helpText}</p>
          <textarea
            autoFocus
            value={note}
            onChange={e => setNote(e.target.value)}
            rows={4}
            placeholder={placeholder}
            className="w-full text-sm rounded-lg px-3 py-2 outline-none resize-none"
            style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
          />
          <p className="text-xs -mt-2" style={{ color: 'var(--text-faint)' }}>Markdown pris en charge (gras, listes, code…) — rendu à l'affichage.</p>
          <div>
            <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Validé par</label>
            <select
              value={validator}
              onChange={e => setValidator(e.target.value)}
              className="w-full text-sm rounded-lg px-3 py-2 outline-none"
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
            >
              <option value="">Sélectionner un analyste…</option>
              {names.map(name => <option key={name} value={name}>{name}</option>)}
            </select>
          </div>
          {showReviewDate && (
            <div>
              <label className="text-xs font-semibold uppercase tracking-wide block mb-1.5" style={{ color: 'var(--text-muted)' }}>Date de revue</label>
              <input
                type="date"
                value={reviewDate}
                onChange={e => setReviewDate(e.target.value)}
                className="w-full text-sm rounded-lg px-3 py-2 outline-none"
                style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
              />
              <p className="text-xs mt-1" style={{ color: 'var(--text-faint)' }}>Le risque accepté sera signalé « en retard de revue » passé cette date — jamais rouvert automatiquement.</p>
            </div>
          )}
          <div className="flex justify-end gap-2 pt-1">
            <button onClick={onClose}
              className="text-xs px-3 py-2 rounded-lg font-medium"
              style={{ background: 'var(--bg-secondary)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}
            >Annuler</button>
            <button onClick={confirm} disabled={noteMissing || !validator || reviewDateMissing || saving}
              className="text-xs px-3 py-2 rounded-lg font-medium disabled:opacity-50"
              style={{ background: `${color}26`, color, border: `1px solid ${color}59` }}
            >{saving ? 'Enregistrement…' : confirmLabel}</button>
          </div>
        </div>
      </div>
    </div>
  )
}

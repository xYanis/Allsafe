import { useState } from 'react'
import { useAnalysts } from '../contexts/AnalystContext.jsx'
import { bulkValidate } from '../api/client.js'

const SIGNAL_LABEL = {
  patch_detected: '✅ Patch détecté (build/KB)',
  date_heuristic: '📅 Signal indicatif (date)',
}

// Lots plutôt qu'un seul appel avec toute la sélection : chaque lot donne un point
// de progression (demande explicite, 08/08/2026) — sans ça, une seule requête pour
// 129 vulns revient quasi instantanément côté serveur (pas d'I/O externe, juste des
// écritures DB) et une barre de progression n'aurait jamais le temps de s'animer.
const CHUNK_SIZE = 20

export default function BulkValidateModal({ items, onClose, onConfirm }) {
  const { names: ANALYSTS } = useAnalysts()
  // Présélection au signal formel (patch_detected) uniquement — le signal indicatif
  // (date_heuristic) reste sélectionnable à la main mais n'est pas coché par défaut,
  // pour ne pas mélanger "correctif détecté" et simple ancienneté dans un même geste.
  const [selected, setSelected] = useState(() => new Set(items.filter(i => i.signal === 'patch_detected').map(i => i.id)))
  const [validator, setValidator] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [progress, setProgress] = useState(null) // null | { done, total, applied }

  function toggle(id) {
    setSelected(s => {
      const next = new Set(s)
      if (next.has(id)) next.delete(id); else next.add(id)
      return next
    })
  }

  function toggleAll() {
    setSelected(s => s.size === items.length ? new Set() : new Set(items.map(i => i.id)))
  }

  async function handleConfirm() {
    if (!validator || selected.size === 0) return
    setSubmitting(true)
    const ids = [...selected]
    const total = ids.length
    let done = 0
    let applied = 0
    setProgress({ done, total, applied })
    try {
      for (let i = 0; i < ids.length; i += CHUNK_SIZE) {
        const chunk = ids.slice(i, i + CHUNK_SIZE)
        const r = await bulkValidate(chunk, validator)
        applied += r.data.applied?.length || 0
        done += chunk.length
        setProgress({ done, total, applied })
      }
      onConfirm(applied, validator)
    } finally {
      setSubmitting(false)
      setProgress(null)
    }
  }

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 animate-backdrop-in modal-backdrop" onClick={onClose}>
      <div className="max-w-3xl w-full max-h-[85vh] flex flex-col rounded-2xl animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
          <div>
            <h2 className="font-semibold text-lg" style={{ color: 'var(--text-primary)' }}>Validation groupée — CRITICAL</h2>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
              Candidats avec signal de correctif positif ({items.length}) — vous restez décisionnaire ligne par ligne, rien n'est validé automatiquement.
              Justification générée automatiquement par actif ("Correctif détecté sur…") — seul le validateur reste à choisir.
            </p>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg" style={{ color: 'var(--text-muted)' }}>
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>

        <div className="overflow-y-auto flex-1">
          <table className="w-full text-sm">
            <thead>
              <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)' }}>
                <th className="px-4 py-2.5">
                  <input type="checkbox" checked={selected.size === items.length && items.length > 0} onChange={toggleAll} className="w-3.5 h-3.5 accent-blue-500" />
                </th>
                <th className="text-left px-2 py-2.5 text-xs font-semibold uppercase" style={{ color: 'var(--text-muted)' }}>CVE</th>
                <th className="text-left px-2 py-2.5 text-xs font-semibold uppercase" style={{ color: 'var(--text-muted)' }}>Actif</th>
                <th className="text-left px-2 py-2.5 text-xs font-semibold uppercase" style={{ color: 'var(--text-muted)' }}>Publiée</th>
                <th className="text-left px-2 py-2.5 text-xs font-semibold uppercase" style={{ color: 'var(--text-muted)' }}>Signal</th>
              </tr>
            </thead>
            <tbody>
              {items.map(v => (
                <tr key={v.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                  <td className="px-4 py-2.5">
                    <input type="checkbox" checked={selected.has(v.id)} onChange={() => toggle(v.id)} className="w-3.5 h-3.5 accent-blue-500" />
                  </td>
                  <td className="px-2 py-2.5 font-mono text-xs font-semibold" style={{ color: '#58a6ff' }}>{v.cve?.cve_id}</td>
                  <td className="px-2 py-2.5 text-xs" style={{ color: 'var(--text-secondary)' }}>{v.asset?.name}</td>
                  <td className="px-2 py-2.5 text-xs" style={{ color: 'var(--text-muted)' }}>
                    {v.cve?.published ? new Date(v.cve.published).toLocaleDateString('fr-FR') : '—'}
                    {v.over_a_year && (
                      <span className="ml-1.5 px-1.5 py-0.5 rounded" style={{ background: 'rgba(139,148,158,0.15)', color: 'var(--text-muted)' }}>{'>'} 1 an</span>
                    )}
                  </td>
                  <td className="px-2 py-2.5 text-xs" title={v.patch_check_details || ''} style={{ color: v.signal === 'patch_detected' ? '#3fb950' : '#58a6ff' }}>
                    {SIGNAL_LABEL[v.signal] || v.signal}
                  </td>
                </tr>
              ))}
              {items.length === 0 && (
                <tr><td colSpan={5} className="px-4 py-10 text-center text-sm" style={{ color: 'var(--text-muted)' }}>Aucun candidat pour le moment</td></tr>
              )}
            </tbody>
          </table>
        </div>

        {progress && (
          <div className="px-6 pt-3 flex flex-col gap-1.5">
            <div className="flex items-center justify-between text-xs" style={{ color: 'var(--text-muted)' }}>
              <span>Validation en cours — {progress.done}/{progress.total}</span>
              <span>{Math.round((progress.done / progress.total) * 100)}%</span>
            </div>
            <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'rgba(0,0,0,0.2)' }}>
              <div
                className="h-full rounded-full transition-all duration-300 progress-bar-shimmer"
                style={{ width: `${Math.round((progress.done / progress.total) * 100)}%`, background: 'linear-gradient(90deg, #2ea043, #3fb950)' }}
              />
            </div>
          </div>
        )}

        <div className="px-6 py-4 flex items-center justify-between gap-3 flex-wrap" style={{ borderTop: '1px solid var(--border)' }}>
          <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{selected.size} sélectionnée(s)</span>
          <div className="flex items-center gap-2">
            <select value={validator} onChange={e => setValidator(e.target.value)} disabled={submitting}
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 8, color: 'var(--text-secondary)', padding: '6px 12px', fontSize: 13, outline: 'none' }}
            >
              <option value="">Validé par…</option>
              {ANALYSTS.map(name => <option key={name} value={name}>{name}</option>)}
            </select>
            <button
              onClick={handleConfirm}
              disabled={!validator || selected.size === 0 || submitting}
              className="text-xs px-3 py-2 rounded-lg font-medium disabled:opacity-40"
              style={{ background: 'rgba(63,185,80,0.15)', color: '#3fb950', border: '1px solid rgba(63,185,80,0.35)' }}
            >
              {submitting ? 'Validation…' : `✓ Marquer comme corrigé (${selected.size})`}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// Autres actifs concernés par la même CVE (04/08/2026) — quand une CVE déjà
// traitée sur un serveur réapparaît sur un autre, retrouver directement le
// diagnostic/la justification posée là-bas plutôt que de rechercher à nouveau
// les mêmes informations sur la CVE. Lecture seule ; "Réutiliser" ne fait que
// pré-remplir l'annotation de CETTE ligne, jamais d'action sur l'autre actif.

const STATUS_STYLES = {
  open:            { background: 'rgba(248,81,73,0.1)',   color: '#f85149', border: '1px solid rgba(248,81,73,0.25)'   },
  in_progress:     { background: 'rgba(251,143,68,0.1)',  color: '#fb8f44', border: '1px solid rgba(251,143,68,0.25)'  },
  patched:         { background: 'rgba(63,185,80,0.1)',   color: '#3fb950', border: '1px solid rgba(63,185,80,0.25)'   },
  accepted_risk:   { background: 'rgba(139,148,158,0.1)', color: '#8b949e', border: '1px solid rgba(139,148,158,0.25)' },
  awaiting_fix:    { background: 'rgba(210,153,34,0.1)',  color: '#d29922', border: '1px solid rgba(210,153,34,0.25)'  },
  awaiting_fix_partial: { background: 'rgba(210,153,34,0.1)', color: '#d29922', border: '1px dashed rgba(210,153,34,0.4)' },
  false_positive:  { background: 'rgba(139,148,158,0.1)', color: '#8b949e', border: '1px solid rgba(139,148,158,0.25)' },
}
const STATUS_LABELS = { open: 'Ouvert', in_progress: 'En cours', patched: 'Corrigé', accepted_risk: 'Risque accepté', awaiting_fix: 'En attente de correctif', awaiting_fix_partial: 'En attente (partiel)', false_positive: 'Faux positif' }
const RESOLVED = ['patched', 'false_positive', 'accepted_risk']

function MiniStatusBadge({ value }) {
  const style = STATUS_STYLES[value] || STATUS_STYLES.open
  return <span className="inline-block px-2 py-0.5 rounded-md text-xs font-semibold flex-shrink-0" style={style}>{STATUS_LABELS[value] ?? value}</span>
}

function resolvedDate(e) {
  return e.patched_at || e.false_positive_at || e.awaiting_fix_at || null
}

export default function OtherInstancesModal({ cveId, entries, loading, onClose, onReuse }) {
  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 modal-backdrop animate-backdrop-in" onClick={onClose}>
      <div className="max-w-2xl w-full max-h-[80vh] rounded-2xl flex flex-col animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4 flex items-center justify-between flex-shrink-0" style={{ borderBottom: '1px solid var(--border)' }}>
          <div>
            <h2 className="font-semibold font-mono" style={{ color: 'var(--text-primary)' }}>{cveId}</h2>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>Autres actifs concernés par cette CVE</p>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg flex-shrink-0" style={{ color: 'var(--text-muted)' }}>
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>

        <div className="p-6 overflow-y-auto space-y-3">
          {loading ? (
            <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Chargement…</p>
          ) : entries.length === 0 ? (
            <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Aucun autre actif concerné par cette CVE.</p>
          ) : (
            entries.map(e => {
              const justification = e.notes || e.patch_check_details
              const date = resolvedDate(e)
              return (
                <div key={e.vuln_id} className="p-3 rounded-xl" style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)' }}>
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <span className="font-semibold text-sm" style={{ color: 'var(--text-primary)' }}>{e.asset_name}</span>
                    <MiniStatusBadge value={e.status} />
                  </div>
                  {e.validated_by && (
                    <p className="text-xs mb-1" style={{ color: 'var(--text-muted)' }}>
                      Validé par {e.validated_by}{date ? ` — ${new Date(date).toLocaleDateString('fr-FR')}` : ''}
                    </p>
                  )}
                  {justification ? (
                    <p className="text-xs whitespace-pre-wrap" style={{ color: 'var(--text-secondary)' }}>{justification}</p>
                  ) : (
                    <p className="text-xs" style={{ color: 'var(--text-faint)' }}>Aucune annotation enregistrée.</p>
                  )}
                  {RESOLVED.includes(e.status) && justification && onReuse && (
                    <button
                      onClick={() => onReuse(justification)}
                      className="mt-2 text-xs px-2.5 py-1 rounded-lg font-medium"
                      style={{ background: 'rgba(88,166,255,0.1)', color: '#58a6ff', border: '1px solid rgba(88,166,255,0.25)' }}
                    >↩ Réutiliser cette justification</button>
                  )}
                </div>
              )
            })
          )}
        </div>
      </div>
    </div>
  )
}

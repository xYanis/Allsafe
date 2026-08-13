// Historique des transitions de statut d'une vulnérabilité (27/07/2026) —
// prospectif, ne couvre que les transitions survenues depuis sa mise en
// service (cf. backend/services/vuln_history.py). Table plutôt que liste :
// même style que le tableau "Connexions IP" d'AdministrationSecurity.jsx,
// mieux adapté à 5 champs bien typés par ligne qu'un rendu narratif.

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

function MiniStatusBadge({ value }) {
  if (!value) return <span style={{ color: 'var(--text-muted)' }}>—</span>
  const style = STATUS_STYLES[value] || STATUS_STYLES.open
  return <span className="inline-block px-2 py-0.5 rounded-md text-xs font-semibold" style={style}>{STATUS_LABELS[value] ?? value}</span>
}

export default function StatusHistoryModal({ cveId, entries, loading, onClose }) {
  return (
    <div className="fixed inset-0 flex items-center justify-center z-50 p-4 modal-backdrop animate-backdrop-in" onClick={onClose}>
      <div className="max-w-2xl w-full max-h-[80vh] rounded-2xl flex flex-col animate-modal-in" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
        <div className="px-6 py-4 flex items-center justify-between flex-shrink-0" style={{ borderBottom: '1px solid var(--border)' }}>
          <div>
            <h2 className="font-semibold" style={{ color: 'var(--text-primary)' }}>Historique des statuts — {cveId}</h2>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
              Chaque changement de statut, manuel ou automatique, depuis la mise en service de cet historique.
            </p>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg" style={{ color: 'var(--text-muted)' }}>
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>

        <div className="p-6 overflow-y-auto">
          {loading ? (
            <p className="text-sm" style={{ color: 'var(--text-muted)' }}>Chargement…</p>
          ) : entries.length === 0 ? (
            <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
              Aucun changement de statut enregistré depuis la mise en service de cet historique
              (27/07/2026) — ne couvre pas les transitions antérieures.
            </p>
          ) : (
            <div className="rounded-lg overflow-hidden" style={{ border: '1px solid var(--border)' }}>
              <table className="w-full text-xs">
                <thead>
                  <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)' }}>
                    {['Date', 'Ancien statut', 'Nouveau statut', 'Validateur', 'Raison'].map(h => (
                      <th key={h} className="text-left px-3 py-2 font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {entries.map((e, i) => (
                    <tr key={i} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                      <td className="px-3 py-2 whitespace-nowrap" style={{ color: 'var(--text-secondary)' }}>
                        {e.changed_at ? new Date(e.changed_at).toLocaleString('fr-FR') : '—'}
                      </td>
                      <td className="px-3 py-2"><MiniStatusBadge value={e.old_status} /></td>
                      <td className="px-3 py-2"><MiniStatusBadge value={e.new_status} /></td>
                      <td className="px-3 py-2" style={{ color: 'var(--text-secondary)' }}>{e.validated_by || '—'}</td>
                      <td className="px-3 py-2" style={{ color: 'var(--text-muted)' }}>{e.notes || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// Statut d'une Vulnerability (open/in_progress/patched/accepted_risk/awaiting_fix/
// awaiting_fix_partial/false_positive) — extrait de Vulnerabilities.jsx le
// 07/08/2026 quand PendingUpdatesModal.jsx en a eu besoin en second (cf. principe
// scalable CLAUDE.md : extraire dès qu'une deuxième page a besoin de la même
// logique non triviale), même esprit que SeverityBadge.jsx/NetworkStatusBadge.jsx.
// Opacités (0.12/0.3) et gabarit alignés sur SeverityBadge.jsx/CriticiteBadge.jsx (11/08/2026,
// tour visuel) — ce badge s'affiche côte à côte avec eux dans les mêmes lignes de tableau
// (Dashboard/Vulnerabilities), un fond/texte légèrement plus petits/pâles que ses voisins
// immédiats se voyait à l'usage.
const STATUS_STYLES = {
  open:                 { background: 'rgba(248,81,73,0.12)',   color: '#f85149', border: '1px solid rgba(248,81,73,0.3)'   },
  in_progress:          { background: 'rgba(251,143,68,0.12)',  color: '#fb8f44', border: '1px solid rgba(251,143,68,0.3)'  },
  patched:              { background: 'rgba(63,185,80,0.12)',   color: '#3fb950', border: '1px solid rgba(63,185,80,0.3)'   },
  accepted_risk:        { background: 'rgba(139,148,158,0.12)', color: '#8b949e', border: '1px solid rgba(139,148,158,0.3)' },
  awaiting_fix:         { background: 'rgba(210,153,34,0.12)',  color: '#d29922', border: '1px solid rgba(210,153,34,0.3)'  },
  awaiting_fix_partial: { background: 'rgba(210,153,34,0.12)',  color: '#d29922', border: '1px dashed rgba(210,153,34,0.4)' },
  false_positive:       { background: 'rgba(139,148,158,0.12)', color: '#8b949e', border: '1px solid rgba(139,148,158,0.3)' },
}
export const STATUS_LABELS = { open: 'Ouvert', in_progress: 'En cours', patched: 'Corrigé', accepted_risk: 'Risque accepté', awaiting_fix: 'En attente de correctif', awaiting_fix_partial: 'En attente (partiel)', false_positive: 'Faux positif' }

export default function StatusBadge({ value }) {
  const style = STATUS_STYLES[value] || STATUS_STYLES.open
  return (
    <span style={{ ...style, borderRadius: 6, padding: '2px 8px', fontSize: 11, fontWeight: 600, letterSpacing: '0.04em', display: 'inline-block' }}>
      {STATUS_LABELS[value] ?? value}
    </span>
  )
}

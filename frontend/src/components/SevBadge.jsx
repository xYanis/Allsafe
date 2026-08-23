// Badge de sévérité (critical/important/informational) d'un item de veille — extrait de
// Watch.jsx (23/08/2026, demande explicite : le même badge manquait sur Fuite de données,
// alors que la sévérité est déjà calculée côté backend pour toutes les sources, y compris
// "fuite" — juste jamais affichée sur cette page-là).
// Exportés en plus du composant : Watch.jsx s'en sert aussi directement dans le select de
// sévérité de la modale de traitement (pas juste un badge en lecture seule).
export const SEV_STYLES = {
  critical:      { background: 'rgba(248,81,73,0.12)',  color: '#f85149', border: '1px solid rgba(248,81,73,0.3)'  },
  important:     { background: 'rgba(251,143,68,0.12)', color: '#fb8f44', border: '1px solid rgba(251,143,68,0.3)' },
  informational: { background: 'rgba(88,166,255,0.12)', color: '#58a6ff', border: '1px solid rgba(88,166,255,0.3)' },
}
export const SEV_LABELS = { critical: 'Critique', important: 'Important', informational: 'Informatif' }

export default function SevBadge({ value }) {
  const s = SEV_STYLES[value] || SEV_STYLES.informational
  return (
    <span style={{ ...s, borderRadius: 6, padding: '2px 8px', fontSize: 11, fontWeight: 600, letterSpacing: '0.04em', display: 'inline-block' }}>
      {SEV_LABELS[value] ?? value}
    </span>
  )
}

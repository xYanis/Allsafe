// Échelle dédiée au module Incidents (Critique/Majeur/Mineur) — distincte de la
// sévérité CVSS (SeverityBadge.jsx), donc pas de réutilisation de ce composant.
const SEV_STYLES = {
  critical: { background: 'rgba(248,81,73,0.12)',  color: '#f85149', border: '1px solid rgba(248,81,73,0.3)'  },
  major:    { background: 'rgba(251,143,68,0.12)', color: '#fb8f44', border: '1px solid rgba(251,143,68,0.3)' },
  minor:    { background: 'rgba(88,166,255,0.12)', color: '#58a6ff', border: '1px solid rgba(88,166,255,0.3)' },
}
const SEV_LABELS = { critical: 'Critique', major: 'Majeur', minor: 'Mineur' }

export default function IncidentSeverityBadge({ value }) {
  const s = SEV_STYLES[value] || SEV_STYLES.minor
  return (
    <span style={{ ...s, borderRadius: 6, padding: '2px 8px', fontSize: 11, fontWeight: 600, letterSpacing: '0.04em', display: 'inline-block' }}>
      {SEV_LABELS[value] ?? value}
    </span>
  )
}

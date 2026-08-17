const STYLES = {
  CRITICAL: { background: 'rgba(248,81,73,0.12)',  color: '#f85149', border: '1px solid rgba(248,81,73,0.3)'  },
  HIGH:     { background: 'rgba(251,143,68,0.12)', color: '#fb8f44', border: '1px solid rgba(251,143,68,0.3)' },
  MEDIUM:   { background: 'rgba(210,153,34,0.12)', color: '#d29922', border: '1px solid rgba(210,153,34,0.3)' },
  LOW:      { background: 'rgba(63,185,80,0.12)',  color: '#3fb950', border: '1px solid rgba(63,185,80,0.3)'  },
  PATCHED:  { background: 'rgba(63,185,80,0.12)',  color: '#3fb950', border: '1px solid rgba(63,185,80,0.3)'  },
  INFO:     { background: 'rgba(88,166,255,0.12)', color: '#58a6ff', border: '1px solid rgba(88,166,255,0.3)' },
}

const DEFAULT = { background: 'rgba(139,148,158,0.12)', color: '#8b949e', border: '1px solid rgba(139,148,158,0.3)' }

// minWidth (17/08/2026) : toutes les sévérités rendent à la même largeur que CRITICAL (la plus
// longue, ~65px mesuré), plutôt que chacune à sa largeur naturelle — sinon le badge Metasploit
// d'ExploitBadge.jsx (ancré au bord droit du conteneur, dimensionné par la largeur de ce badge)
// débordait au-delà de "HIGH"/"MEDIUM"/"LOW", plus étroits. textAlign centre le texte plus court
// dans cette largeur fixe au lieu de le laisser collé à gauche.
export default function SeverityBadge({ value }) {
  const key = (value || '').toUpperCase()
  const style = STYLES[key] || DEFAULT
  return (
    <span style={{
      ...style, borderRadius: 6, padding: '2px 8px', fontSize: 11, fontWeight: 600, letterSpacing: '0.04em',
      display: 'inline-block', minWidth: 65, boxSizing: 'border-box', textAlign: 'center',
    }}>
      {key || '—'}
    </span>
  )
}

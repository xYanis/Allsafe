const STYLES = {
  HAUTE:   { background: 'rgba(248,81,73,0.12)',  color: '#f85149', border: '1px solid rgba(248,81,73,0.3)'  },
  MOYENNE: { background: 'rgba(88,166,255,0.12)', color: '#58a6ff', border: '1px solid rgba(88,166,255,0.3)' },
  FAIBLE:  { background: 'rgba(139,148,158,0.12)', color: '#8b949e', border: '1px solid rgba(139,148,158,0.3)' },
}

const LABELS = { HAUTE: 'Haute', MOYENNE: 'Moyenne', FAIBLE: 'Faible' }

export default function CriticiteBadge({ value }) {
  const key = (value || 'moyenne').toUpperCase()
  const style = STYLES[key] || STYLES.MOYENNE
  return (
    <span style={{ ...style, borderRadius: 6, padding: '2px 8px', fontSize: 11, fontWeight: 600, letterSpacing: '0.04em', display: 'inline-block' }}>
      {LABELS[key] || 'Moyenne'}
    </span>
  )
}

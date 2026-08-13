// Frise horizontale générique — vue d'ensemble en un coup d'œil, complémentaire au journal
// détaillé (IncidentTimeline.jsx) qui reste la source d'audit complète en dessous. Utilisée en
// haut de IncidentDetailModal.jsx et CrisisDetailModal.jsx (31/07/2026).
//
// `steps`: [{ key, label, sublabel?, state }], state ∈ 'done' | 'current' | 'overdue' | 'pending' | 'skipped'.
// - done     : étape franchie (coche pleine, couleur du module)
// - current  : prochaine étape attendue (cercle vide, pastille couleur module)
// - overdue  : prochaine étape attendue mais échéance dépassée (rouge)
// - pending  : pas encore atteinte, sans urgence particulière (cercle vide, gris)
// - skipped  : non applicable à ce cas (ex : NIS 2 non requis) — pointillé, gris, jamais rouge

function StepCircle({ state, color }) {
  const size = 20
  const base = { width: size, height: size, borderRadius: '50%', flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }
  if (state === 'done') {
    return (
      <div style={{ ...base, background: color }}>
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="var(--bg-card)" strokeWidth={3.5} strokeLinecap="round" strokeLinejoin="round">
          <path d="M5 13l4 4L19 7" />
        </svg>
      </div>
    )
  }
  if (state === 'overdue') {
    return (
      <div style={{ ...base, background: '#f85149' }}>
        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth={3.5} strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 8v5M12 16h.01" />
        </svg>
      </div>
    )
  }
  if (state === 'current') {
    return (
      <div style={{ ...base, border: `2px solid ${color}`, background: 'var(--bg-card)' }}>
        <div style={{ width: 7, height: 7, borderRadius: '50%', background: color }} />
      </div>
    )
  }
  if (state === 'skipped') {
    return <div style={{ ...base, border: '1px dashed var(--border)' }} />
  }
  return <div style={{ ...base, border: '1px solid var(--border)', background: 'var(--bg-card)' }} /> // pending
}

export default function Stepper({ steps, color }) {
  return (
    <div className="flex items-start w-full overflow-x-auto">
      {steps.map((s, i) => (
        <div key={s.key} className="flex items-start" style={{ flex: i === steps.length - 1 ? '0 0 auto' : '1 1 0' }}>
          <div className="flex flex-col items-center" style={{ minWidth: 68, maxWidth: 96 }}>
            <StepCircle state={s.state} color={color} />
            <p className="text-[10px] font-semibold uppercase tracking-wide mt-1.5 text-center leading-tight"
              style={{ color: s.state === 'overdue' ? '#f85149' : (s.state === 'pending' || s.state === 'skipped') ? 'var(--text-faint)' : 'var(--text-secondary)' }}>
              {s.label}
            </p>
            {s.sublabel && (
              <p className="text-[9px] mt-0.5 text-center leading-tight" style={{ color: 'var(--text-faint)' }}>{s.sublabel}</p>
            )}
          </div>
          {i < steps.length - 1 && (
            <div className="h-px flex-1 mt-[9px] mx-1" style={{ background: s.state === 'done' ? color : 'var(--border)', minWidth: 16 }} />
          )}
        </div>
      ))}
    </div>
  )
}

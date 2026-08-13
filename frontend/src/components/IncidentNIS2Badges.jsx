import { milestoneStatus, MILESTONE_LABELS } from '../utils/nis2Countdown.js'

const MILESTONES = ['early_warning', 'incident_notification', 'final_report']

// Les 3 pastilles de compte à rebours — affichées seulement si l'incident est
// qualifié `requires_notification` (jamais automatique, cf. nis2_deadlines.py).
export default function IncidentNIS2Badges({ incident, compact = false }) {
  if (!incident.requires_notification) return null

  return (
    <div className={`flex ${compact ? 'flex-wrap gap-1' : 'flex-col gap-1.5'}`}>
      {MILESTONES.map(m => {
        const due = incident[`${m}_due_at`]
        const sent = incident[`${m}_sent_at`]
        const s = milestoneStatus(m, due, sent)
        const label = compact ? MILESTONE_LABELS[m].split(' ')[0] : MILESTONE_LABELS[m]
        return (
          <span key={m} title={MILESTONE_LABELS[m]}
            className="text-xs font-medium px-1.5 py-0.5 rounded inline-block whitespace-nowrap"
            style={{ background: `${s.color}22`, color: s.color, border: `1px solid ${s.color}55` }}>
            {label} — {s.label}
          </span>
        )
      })}
    </div>
  )
}

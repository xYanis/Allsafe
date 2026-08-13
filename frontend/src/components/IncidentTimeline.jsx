import MarkdownNote from './MarkdownNote.jsx'
import PageLoader from './PageLoader.jsx'

const EVENT_LABELS = {
  created: 'Incident créé',
  status_change: 'Changement de statut',
  note: 'Note',
  notification_qualified: 'Qualifié à notifier (NIS 2)',
  notification_unqualified: 'Déqualifié',
  milestone_sent: 'Jalon envoyé',
  aware_at_changed: 'Prise de connaissance modifiée',
}

function fmt(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('fr-FR')
}

// Vue chronologique — cartes, pas un tableau plat comme StatusHistoryModal.jsx :
// les entrées sont hétérogènes (statut, note markdown, jalon envoyé). `labels` : réutilisée
// par CrisisDetailModal.jsx avec son propre vocabulaire d'event_type (cf. CRISIS_EVENT_LABELS).
export default function IncidentTimeline({ entries, loading, labels = EVENT_LABELS }) {
  if (loading) return <PageLoader size="sm" />
  if (!entries || entries.length === 0) {
    return <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Aucun évènement.</p>
  }

  return (
    <div className="space-y-3">
      {entries.map(e => (
        <div key={e.id} className="pl-3" style={{ borderLeft: '2px solid var(--border)' }}>
          <div className="flex items-center justify-between gap-2">
            <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
              {labels[e.event_type] || e.event_type}
            </p>
            <span className="text-xs flex-shrink-0" style={{ color: 'var(--text-faint)' }}>{fmt(e.occurred_at)}</span>
          </div>
          <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
            {e.author}
            {e.old_value && e.new_value ? ` — ${e.old_value} → ${e.new_value}` : e.new_value && e.event_type !== 'note' ? ` — ${e.new_value}` : ''}
          </p>
          {e.notes && <div className="mt-1"><MarkdownNote text={e.notes} className="text-xs" /></div>}
        </div>
      ))}
    </div>
  )
}

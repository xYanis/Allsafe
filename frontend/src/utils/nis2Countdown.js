// Statut d'un jalon d'échéance NIS 2 (badge compte à rebours) — pure, sans I/O.
// Seuils absolus par jalon, pas proportionnels : un pourcentage traiterait
// différemment une échéance de 24h et une de 1 mois, alors que "il reste moins
// de 4h" a le même sens d'urgence quelle que soit la durée totale du délai.
const WARN_HOURS = {
  early_warning: 4,            // < 4h restantes = urgent
  incident_notification: 12,   // < 12h restantes = urgent
  final_report: 24 * 3,        // < 3 jours restantes = urgent
}

export const MILESTONE_LABELS = {
  early_warning: 'Alerte précoce (24h)',
  incident_notification: 'Notification (72h)',
  final_report: 'Rapport final (1 mois)',
}

export function milestoneStatus(milestone, dueAt, sentAt, now = new Date()) {
  if (sentAt) return { state: 'sent', label: 'Envoyé', color: '#8b949e' }
  if (!dueAt) return { state: 'none', label: '—', color: 'var(--text-muted)' }

  const hoursLeft = (new Date(dueAt).getTime() - now.getTime()) / 3600000
  const warnHours = WARN_HOURS[milestone] ?? 12

  if (hoursLeft < 0) return { state: 'overdue', label: 'Dépassé', color: '#f85149' }
  if (hoursLeft < warnHours) return { state: 'imminent', label: 'Urgent', color: '#fb8f44' }
  return { state: 'ok', label: 'Dans les temps', color: '#3fb950' }
}

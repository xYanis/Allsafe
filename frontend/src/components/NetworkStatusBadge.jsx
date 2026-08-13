// État réseau remonté par une sonde externe (Meraki puis PRTG, 04/08/2026, cf.
// services/meraki_matcher.py + services/prtg_matcher.py) — même esprit que
// CriticiteBadge.jsx (petite pastille), affiché à la fois sur Actifs et sur
// Inventaire (choix déjà tranché avec l'utilisateur). `null` (jamais rapproché
// d'un équipement d'aucune sonde) ne rend rien — pas de "—" qui laisserait croire
// à un état constaté plutôt qu'à une absence de donnée. `source` (renvoyé par
// l'API, cf. routers/assets.py) pilote le libellé de la tooltip plutôt qu'un nom
// de sonde codé en dur — un actif peut être suivi par l'une ou l'autre.
const STYLES = {
  online:   { background: 'rgba(63,185,80,0.12)',  color: '#3fb950', border: '1px solid rgba(63,185,80,0.3)'  },
  offline:  { background: 'rgba(248,81,73,0.12)',  color: '#f85149', border: '1px solid rgba(248,81,73,0.3)'  },
  alerting: { background: 'rgba(210,153,34,0.12)', color: '#d29922', border: '1px solid rgba(210,153,34,0.3)' },
  dormant:  { background: 'rgba(139,148,158,0.12)', color: '#8b949e', border: '1px solid rgba(139,148,158,0.3)' },
}
// Exporté (pas seulement local) : le filtre "Statut réseau" d'Actifs.jsx s'appuie
// dessus plutôt que de dupliquer le libellé des 4 statuts possibles.
export const NETWORK_STATUS_LABELS = { online: 'En ligne', offline: 'Hors ligne', alerting: 'Alerte', dormant: 'Veille' }
const SOURCE_LABELS = { meraki: 'Meraki', prtg: 'PRTG' }

// Format relatif pour l'affichage sous le badge (pas la tooltip, qui garde la date
// complète) — "7j", "3h", "42min", "12s" : une seule unité, la plus grande non
// nulle, même esprit que le "il y a ..." déjà affiché nativement par PRTG.
function formatRelative(iso) {
  const diffSec = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000))
  if (diffSec < 60) return `${diffSec}s`
  const diffMin = Math.floor(diffSec / 60)
  if (diffMin < 60) return `${diffMin}min`
  const diffH = Math.floor(diffMin / 60)
  if (diffH < 24) return `${diffH}h`
  const diffJ = Math.floor(diffH / 24)
  return `${diffJ}j`
}

// `compact` (12/08/2026, demande utilisateur — tableau Actifs qui débordait ; repris sur
// Inventaire le 13/08/2026 pour la même colonne) : pastille colorée seule, tout le détail
// (statut, sonde, dates) part dans le `title` au survol — même esprit que ConnectivityDot.jsx,
// qui fait déjà ce compromis pour la connectivité SSH/WinRM. Le mode pill complet reste
// disponible (prop par défaut), ce n'est qu'une variante d'affichage du même composant, pas
// une bascule de logique.
export default function NetworkStatusBadge({ networkStatus, compact = false }) {
  if (!networkStatus?.status) return null
  const style = STYLES[networkStatus.status] || STYLES.dormant
  const sourceLabel = SOURCE_LABELS[networkStatus.source] || networkStatus.source || 'Sonde'
  const date = networkStatus.last_reported_at ? new Date(networkStatus.last_reported_at).toLocaleString('fr-FR') : null
  // `status_since` : uniquement PRTG pour l'instant (lastup_raw/lastdown_raw côté
  // sonde, cf. services/prtg_matcher.py) — None pour Meraki ou un statut "dormant"
  // (surveillance suspendue, "depuis quand" n'a pas de sens fiable).
  const since = networkStatus.status_since ? new Date(networkStatus.status_since).toLocaleString('fr-FR') : null
  const statusLabel = NETWORK_STATUS_LABELS[networkStatus.status] || networkStatus.status

  if (compact) {
    const tooltipLines = [`${statusLabel} — ${sourceLabel}`]
    if (since) tooltipLines.push(`${statusLabel} depuis : ${since}`)
    if (date) tooltipLines.push(`Dernier contact : ${date}`)
    return (
      <span
        title={tooltipLines.join(' — ')}
        style={{ display: 'inline-block', width: 9, height: 9, borderRadius: '50%', background: style.color, boxShadow: `0 0 0 2px ${style.color}33`, flexShrink: 0 }}
      />
    )
  }

  const tooltipLines = [sourceLabel]
  if (since) tooltipLines.push(`${statusLabel} depuis : ${since}`)
  if (date) tooltipLines.push(`Dernier contact : ${date}`)
  return (
    <span style={{ display: 'inline-flex', flexDirection: 'column', gap: 2, alignItems: 'flex-start' }} title={tooltipLines.join(' — ')}>
      <span style={{ ...style, borderRadius: 6, padding: '2px 8px', fontSize: 11, fontWeight: 600, letterSpacing: '0.04em', display: 'inline-block' }}>
        {statusLabel}
      </span>
      {networkStatus.status_since && (
        <span style={{ fontSize: 10, color: 'var(--text-muted)', paddingLeft: 2 }}>
          depuis {formatRelative(networkStatus.status_since)}
        </span>
      )}
    </span>
  )
}

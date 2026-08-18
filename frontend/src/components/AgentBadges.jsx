import OsLogo from './OsLogo.jsx'

// Extrait de Agents.jsx (18/08/2026) — utilisé par la liste ET la page d'historique par
// agent (Agents.jsx + AgentHistory.jsx) : dès la 2e page qui en a besoin, ça passe dans un
// fichier partagé plutôt que d'être dupliqué (cf. CLAUDE.md § principe scalable).

const STATUS_STYLES = {
  enrolled: { background: 'rgba(63,185,80,0.12)', color: '#3fb950', border: '1px solid rgba(63,185,80,0.3)' },
  revoked:  { background: 'rgba(248,81,73,0.12)', color: '#f85149', border: '1px solid rgba(248,81,73,0.3)' },
}

export function StatusBadge({ value }) {
  const s = STATUS_STYLES[value] || STATUS_STYLES.enrolled
  return <span style={{ ...s, borderRadius: 6, padding: '2px 8px', fontSize: 11, fontWeight: 600, display: 'inline-block' }}>
    {value === 'revoked' ? 'Révoqué' : 'Enrôlé'}
  </span>
}

// Pastille de couleur plutôt qu'un pill texte (17/08/2026, demande explicite — moins de
// bruit visuel dans la colonne) : le sens (à jour/mise à jour dispo) reste accessible via
// le tooltip au survol. Version en police mono (--font-mono) — lisibilité/alignement d'un
// numéro de version, cohérent avec le reste de l'app (titres PageHero notamment) — et dans
// la même couleur que la pastille juste à côté, plutôt qu'un gris neutre découplé du sens
// qu'elle porte.
export function VersionBadge({ version, outdated }) {
  if (!version) return <span style={{ color: 'var(--text-muted)' }}>—</span>
  const color = outdated ? '#d29922' : '#3fb950'
  return (
    <span className="inline-flex items-center gap-1.5">
      <span style={{ color, fontFamily: 'var(--font-mono)' }}>{version}</span>
      <span
        title={outdated ? "Une version plus récente de l'agent est disponible" : "Ce poste tourne la dernière version publiée de l'agent"}
        style={{ width: 7, height: 7, borderRadius: '50%', flexShrink: 0, display: 'inline-block', background: color }}
      />
    </span>
  )
}

// État du jeton d'enrôlement ayant servi à créer cet agent (17/08/2026, demande explicite —
// distinct du statut de l'agent lui-même, qui ne dit rien du jeton une fois l'enrôlement fait).
const TOKEN_STATUS_STYLES = {
  active:    { color: '#3fb950', label: 'Actif',   title: "Le jeton d'enrôlement est toujours valide (non expiré, non épuisé)." },
  expired:   { color: '#8b949e', label: 'Expiré',  title: "Le jeton d'enrôlement a dépassé sa date d'expiration." },
  exhausted: { color: '#8b949e', label: 'Épuisé',  title: "Le jeton d'enrôlement a atteint son nombre maximal d'utilisations." },
  revoked:   { color: '#f85149', label: 'Révoqué', title: "Le jeton d'enrôlement a été révoqué après l'enrôlement." },
}

export function TokenStateBadge({ status }) {
  const s = TOKEN_STATUS_STYLES[status] || TOKEN_STATUS_STYLES.revoked
  return (
    <span className="inline-flex items-center gap-1.5" title={s.title}>
      <span style={{ width: 7, height: 7, borderRadius: '50%', flexShrink: 0, display: 'inline-block', background: s.color }} />
      <span style={{ color: 'var(--text-secondary)' }}>{s.label}</span>
    </span>
  )
}

// Distribution précise (ex. "Debian 12", "Windows Server 2019") — distincte de la colonne
// "OS" (juste windows/linux, déclaré par l'agent lui-même) : vient de l'actif rattaché
// (Asset.os/os_version, alimenté par le premier scan). OsLogo.jsx sait déjà distinguer
// Debian/Ubuntu d'un Linux générique à partir de ce texte (même composant que Assets.jsx/
// Inventaire.jsx) — absente tant qu'aucun scan n'a encore eu lieu sur l'actif.
export function DistroBadge({ os, version }) {
  if (!os) return <span style={{ color: 'var(--text-muted)' }}>—</span>
  return (
    <span className="inline-flex items-center gap-1.5" style={{ color: 'var(--text-secondary)' }}>
      <OsLogo os={os} size={16} />
      {os}{version ? ` ${version}` : ''}
    </span>
  )
}

export function formatDateTime(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  return d.toLocaleDateString('fr-FR') + ' ' + d.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' })
}

// Fraîcheur du dernier contact (18/08/2026, remplace l'icône de coupure séparée — jugée
// trompeuse : elle restait affichée jusqu'à 7 jours même une fois l'agent reconnecté
// depuis longtemps, cf. incident réel). Seuils calés sur le rythme normal de l'agent
// (check-in réel toutes les heures, sondage court toutes les 60s qui rafraîchit aussi
// `last_seen_at`, cf. auth_deps.py::require_agent) : une marge confortable avant d'inquiéter
// (vert), une vraie alerte à partir de 24h sans nouvelles.
const FRESHNESS_GREEN_MS  = 2 * 60 * 60 * 1000   // < 2h : rythme normal, rien à signaler
const FRESHNESS_ORANGE_MS = 24 * 60 * 60 * 1000  // 2h-24h : en retard, pas encore alarmant

export function contactFreshness(lastSeenAt) {
  if (!lastSeenAt) return 'red'
  const age = Date.now() - new Date(lastSeenAt).getTime()
  if (age < FRESHNESS_GREEN_MS) return 'green'
  if (age < FRESHNESS_ORANGE_MS) return 'orange'
  return 'red'
}

export const FRESHNESS_COLOR = { green: '#3fb950', orange: '#d29922', red: '#f85149' }
export const FRESHNESS_LABEL = { green: 'À jour', orange: 'En retard', red: 'Hors ligne' }

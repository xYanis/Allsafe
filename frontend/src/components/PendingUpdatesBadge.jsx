// Ventilation système/application des mises à jour en attente (07/08/2026, cf.
// Vulnerability.component_type, routers/assets.py::PENDING_UPDATE_STATUSES) —
// deux pastilles distinctes plutôt qu'un total fusionné : la demande explicite
// était de séparer "système" et "application", pas de dupliquer le total déjà
// visible dans la colonne "Vulnérabilités ouvertes". `component_type` NULL
// (WithSecure, création manuelle, pas encore backfillé) n'apparaît dans aucune
// des deux pastilles — reste comptabilisé dans le total global uniquement.
const STYLE_SYSTEM = { background: 'rgba(88,166,255,0.12)', color: '#58a6ff', border: '1px solid rgba(88,166,255,0.3)' }
const STYLE_APP     = { background: 'rgba(163,113,247,0.12)', color: '#a371f7', border: '1px solid rgba(163,113,247,0.3)' }
const PILL = { borderRadius: 6, padding: '2px 6px', fontSize: 11, fontWeight: 600, whiteSpace: 'nowrap', cursor: 'pointer' }

// `onClick` (07/08/2026) : ouvre PendingUpdatesModal côté page appelante — la
// pastille n'affichait qu'un compte, demande explicite d'accéder au détail
// (liste des CVE) sans quitter Actifs. Optionnel : reste un simple compte
// non cliquable si aucun handler n'est fourni par l'appelant.
export default function PendingUpdatesBadge({ pendingUpdates, onClick }) {
  const system = pendingUpdates?.system || 0
  const application = pendingUpdates?.application || 0
  if (!system && !application) return <span style={{ color: 'var(--text-muted)' }}>—</span>
  const clickable = typeof onClick === 'function'
  return (
    <div className="flex items-center gap-1.5">
      {system > 0 && (
        <span
          style={{ ...STYLE_SYSTEM, ...PILL, cursor: clickable ? 'pointer' : 'default' }}
          title={`${system} mise${system > 1 ? 's' : ''} à jour système en attente${clickable ? ' — cliquer pour le détail' : ''}`}
          onClick={clickable ? onClick : undefined}
        >
          🖥 {system}
        </span>
      )}
      {application > 0 && (
        <span
          style={{ ...STYLE_APP, ...PILL, cursor: clickable ? 'pointer' : 'default' }}
          title={`${application} mise${application > 1 ? 's' : ''} à jour applicative${application > 1 ? 's' : ''} en attente${clickable ? ' — cliquer pour le détail' : ''}`}
          onClick={clickable ? onClick : undefined}
        >
          📦 {application}
        </span>
      )}
    </div>
  )
}

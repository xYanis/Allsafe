// Protocole d'admin non chiffré détecté par test TCP passif sur un actif réseau
// (07/08/2026, cf. Asset.network_compliance, services/network_protocol_check.py —
// switches/pare-feux PRTG/Meraki uniquement, CBR n'a aucun accès identifiant à ces
// équipements contrairement aux serveurs SSH/WinRM). Ne rend rien si "ok"/"unknown"
// (jamais lancé, ou pas d'IP) — même esprit que NetworkStatusBadge.jsx : pas de "—"
// qui laisserait croire à un état constaté plutôt qu'à une absence de donnée.
// `compact` (12/08/2026, demande utilisateur — tableau Actifs qui débordait) : icône seule,
// le détail part dans le `title` au survol — même compromis que NetworkStatusBadge.jsx.
export default function NetworkComplianceBadge({ networkCompliance, compact = false }) {
  const check = networkCompliance?.checks?.[0]
  if (!check || check.status !== 'warn') return null
  const title = `${check.label} — ${check.detail}`
  if (compact) {
    return <span title={title} style={{ color: '#d29922', fontSize: 13, lineHeight: 1, flexShrink: 0 }}>⚠</span>
  }
  return (
    <span
      style={{
        background: 'rgba(210,153,34,0.12)', color: '#d29922', border: '1px solid rgba(210,153,34,0.3)',
        borderRadius: 6, padding: '2px 8px', fontSize: 11, fontWeight: 600, display: 'inline-block',
      }}
      title={title}
    >
      ⚠ {check.detail}
    </span>
  )
}

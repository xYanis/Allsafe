// Pastille de connectivité CBR (04/08/2026) — "cet actif répond-il bien à un scan
// SSH/WinRM ?", à distinguer du badge NetworkStatusBadge (Meraki/PRTG, en ligne/
// hors ligne côté réseau). Basée sur `last_scan_result.reachable` (dernier scan
// tenté, cf. services/asset_scanner.py), pas un statut vérifié en direct à chaque
// affichage — même esprit "instantané" que le reste de l'app.
// N'affiche rien pour un actif réseau (Meraki/PRTG) : ces actifs n'ont pas de
// scan SSH/WinRM applicable, un point gris "jamais scanné" y serait trompeur.
const STYLES = {
  ok:      { background: '#3fb950', boxShadow: '0 0 0 2px rgba(63,185,80,0.25)' },
  failed:  { background: '#f85149', boxShadow: '0 0 0 2px rgba(248,81,73,0.25)' },
  unknown: { background: '#8b949e', boxShadow: '0 0 0 2px rgba(139,148,158,0.25)' },
}

export default function ConnectivityDot({ assetType, reachable, error }) {
  if (assetType === 'network') return null

  const state = reachable === true ? 'ok' : reachable === false ? 'failed' : 'unknown'
  const title = state === 'ok'
    ? 'Bien relié à Allsafe (dernier scan réussi)'
    : state === 'failed'
      ? `Injoignable — dernier scan en échec${error ? ` (${error})` : ''}`
      : 'Jamais scanné'

  return (
    <span
      title={title}
      style={{ ...STYLES[state], display: 'inline-block', width: 8, height: 8, borderRadius: '50%', flexShrink: 0 }}
    />
  )
}

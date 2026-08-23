// Couleur par source de veille (Veille technologique + Fuite de données, même modèle
// WatchItem côté backend) — extrait le 23/08/2026 de FuiteDeDonnees.jsx (seule page à
// avoir déjà cette logique) pour que Watch.jsx en bénéficie aussi sans dupliquer.
export const SOURCE_COLORS = {
  zataz: '#f0883e',
  fuitesinfos: '#58a6ff',
  'ransomware-live': '#f85149',
  'databreaches-net': '#d29922',
  hibp: '#bc8cff',
  'cert-fr-avis': '#3fb950',
  'cert-fr-alerte': '#f85149',
  anssi: '#58a6ff',
  sekoia: '#bc8cff',
  cybermalveillance: '#d29922',
}

// Palette de repli pour les sources personnalisées (nombre arbitraire, pas de couleur
// pré-assignée possible) — dérivée du slug pour rester stable d'un chargement à l'autre.
const CUSTOM_PALETTE = ['#39c5cf', '#db61a2', '#7ee787', '#ffa657', '#79c0ff', '#e3b341']
export function colorForSlug(slug) {
  let h = 0
  for (const c of slug || '') h = (h * 31 + c.charCodeAt(0)) >>> 0
  return CUSTOM_PALETTE[h % CUSTOM_PALETTE.length]
}

export function sourceColor(source) {
  return SOURCE_COLORS[source] || colorForSlug(source || '')
}

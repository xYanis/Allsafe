// Extrait d'Assets.jsx/Inventaire.jsx (18/08/2026) — même implémentation dupliquée à
// l'identique dans les deux pages, AgentHistory.jsx en aurait fait une troisième copie.
export function formatDisks(disks) {
  if (!disks || disks.length === 0) return '—'
  return disks.map(d => `${d.name} ${d.total_gb ?? '?'} Go`).join(', ')
}
